import AppKit
import SwiftUI

/// Formatting changes attributes only, never characters, so it never touches what is verified.
/// Lists are the exception: their markers are typed characters and are recorded as such.

/// What the cursor or selection currently looks like, for the format bar.
struct FormatState: Equatable {
    var style = TextStyle.normal
    var family = FontChoice.sans.name
    var size: CGFloat = 17
    var bold = false, italic = false, underline = false, strike = false
    var alignment = NSTextAlignment.natural
    var spacing: CGFloat = 1.3
}

enum TextStyle: String, CaseIterable, Identifiable {
    /// How the style looks in the picker: same hierarchy as the page, scaled down.
    var preview: Font {
        switch self {
        case .title: return .system(size: 22, weight: .bold)
        case .heading1: return .system(size: 18, weight: .bold)
        case .heading2: return .system(size: 15.5, weight: .bold)
        case .heading3: return .system(size: 14, weight: .semibold)
        case .code: return .system(size: 13, design: .monospaced)
        case .normal: return .system(size: 13.5)
        }
    }
    case normal = "Normal text", title = "Title", heading1 = "Heading 1", heading2 = "Heading 2", heading3 = "Heading 3", code = "Code"
    var id: String { rawValue }
    var size: CGFloat { [.title: 30, .heading1: 24, .heading2: 20, .heading3: 18, .code: 15][self] ?? 17 }
    var bold: Bool { self != .normal && self != .code }
    /// Recognises a style from a font, since RTF keeps fonts but not style names.
    static func of(_ font: NSFont) -> TextStyle {
        if font.fontDescriptor.symbolicTraits.contains(.monoSpace) && font.pointSize == 15 { return .code }
        let bold = font.fontDescriptor.symbolicTraits.contains(.bold)
        return allCases.first { $0 != .normal && $0 != .code && $0.size == font.pointSize && bold } ?? .normal
    }
}

/// A short, Docs-like list of fonts: the system families first, then classic Mac fonts.
struct FontChoice: Identifiable, Equatable {
    let name: String
    let family: String?
    let design: NSFontDescriptor.SystemDesign?
    var id: String { name }
    /// This font at picker size, so the list shows what each one looks like.
    var preview: Font {
        if let family { return .custom(family, size: 15) }
        switch design {
        case .serif: return .system(size: 15, design: .serif)
        case .rounded: return .system(size: 15, design: .rounded)
        case .monospaced: return .system(size: 14, design: .monospaced)
        default: return .system(size: 15)
        }
    }
    static let sans = FontChoice(name: "Sans", family: nil, design: .default)
    static let all: [FontChoice] = [
        sans, FontChoice(name: "Serif", family: nil, design: .serif), FontChoice(name: "Rounded", family: nil, design: .rounded),
        FontChoice(name: "Mono", family: nil, design: .monospaced),
        FontChoice(name: "Georgia", family: "Georgia", design: nil), FontChoice(name: "Charter", family: "Charter", design: nil),
        FontChoice(name: "Palatino", family: "Palatino", design: nil), FontChoice(name: "Times New Roman", family: "Times New Roman", design: nil),
        FontChoice(name: "Avenir Next", family: "Avenir Next", design: nil),
        FontChoice(name: "Courier New", family: "Courier New", design: nil),
    ].filter { $0.family == nil || NSFontManager.shared.availableFontFamilies.contains($0.family!) }

    /// This font in this family, keeping size, bold and italic.
    func font(like current: NSFont, size: CGFloat? = nil, bold: Bool? = nil) -> NSFont {
        let size = size ?? current.pointSize
        let traits = current.fontDescriptor.symbolicTraits
        let wantsBold = bold ?? traits.contains(.bold)
        var font: NSFont
        if let design {
            let base = NSFont.systemFont(ofSize: size, weight: wantsBold ? .bold : .regular)
            font = base.fontDescriptor.withDesign(design).flatMap { NSFont(descriptor: $0, size: size) } ?? base
        } else {
            font = NSFontManager.shared.font(withFamily: family!, traits: [], weight: 5, size: size)
                ?? NSFont(name: family!, size: size) ?? .systemFont(ofSize: size)
            if wantsBold { font = NSFontManager.shared.convert(font, toHaveTrait: .boldFontMask) }
        }
        if traits.contains(.italic) { font = NSFontManager.shared.convert(font, toHaveTrait: .italicFontMask) }
        return font
    }
    static func of(_ font: NSFont) -> FontChoice {
        let family = font.familyName ?? ""
        if family.hasPrefix(".") || family.hasPrefix("SF ") {
            if family.contains("Serif") || family.hasPrefix("New York") { return all[1] }
            if family.contains("Rounded") { return all[2] }
            if family.contains("Mono") { return all[3] }
            return sans
        }
        return all.first { $0.family == family } ?? FontChoice(name: family, family: family, design: nil)
    }
}

/// Text and highlight colors that read on both light and dark pages.
enum Swatch: String, CaseIterable, Identifiable {
    case gray, brown, red, orange, yellow, green, blue, purple, pink
    var id: String { rawValue }
    var color: NSColor {
        let value: UInt32 = [.gray: 0x8E8E8A, .brown: 0x9A6E58, .red: 0xE0473E, .orange: 0xE07C24, .yellow: 0xD4A017,
                             .green: 0x2E9E6B, .blue: 0x2F80ED, .purple: 0x9065B0, .pink: 0xD1508F][self]!
        return NSColor(srgbRed: CGFloat((value >> 16) & 0xff) / 255, green: CGFloat((value >> 8) & 0xff) / 255, blue: CGFloat(value & 0xff) / 255, alpha: 1)
    }
    var highlight: NSColor { color.withAlphaComponent(0.28) }
}

extension EditorCommands {
    static let defaultFont = NSFont.systemFont(ofSize: 17)

    /// Applies an attribute change to the selection (or its paragraphs), or to what is typed next
    /// when nothing is selected. Undoable as one step.
    func format(paragraphs: Bool = false, _ change: (NSTextStorage, NSRange) -> Void,
                typing: ((inout [NSAttributedString.Key: Any]) -> Void)? = nil) {
        guard let editor, let storage = editor.textStorage else { return }
        editor.window?.makeFirstResponder(editor)
        let selection = editor.selectedRange()
        let range = paragraphs ? (editor.string as NSString).paragraphRange(for: selection) : selection
        let before = editor.attributedString(), beforeTyping = editor.typingAttributes
        if range.length > 0 { storage.beginEditing(); change(storage, range); storage.endEditing() }
        if let typing, selection.length == 0 || paragraphs { var attributes = editor.typingAttributes; typing(&attributes); editor.typingAttributes = attributes }
        registerFormattingUndo(editor: editor, content: before, typing: beforeTyping)
        persist?()
        refreshSelection()
    }
    private func eachFont(_ storage: NSTextStorage, _ range: NSRange, _ convert: (NSFont) -> NSFont) {
        storage.enumerateAttribute(.font, in: range) { value, subrange, _ in
            storage.addAttribute(.font, value: convert(value as? NSFont ?? Self.defaultFont), range: subrange)
        }
    }
    private func changeFont(paragraphs: Bool = false, _ convert: @escaping (NSFont) -> NSFont) {
        format(paragraphs: paragraphs, { storage, range in self.eachFont(storage, range, convert) },
               typing: { $0[.font] = convert($0[.font] as? NSFont ?? Self.defaultFont) })
    }

    func setStyle(_ style: TextStyle) {
        changeFont(paragraphs: true) { font in
            style == .code ? .monospacedSystemFont(ofSize: style.size, weight: .regular)
                : FontChoice.of(font).font(like: font, size: style.size, bold: style.bold)
        }
    }
    func setFamily(_ choice: FontChoice) { changeFont { choice.font(like: $0) } }
    func setSize(_ size: CGFloat) {
        let size = min(96, max(8, size))
        changeFont { NSFont(descriptor: $0.fontDescriptor, size: size) ?? $0 }
    }
    func setColor(_ swatch: Swatch?) {
        let color = swatch?.color ?? .labelColor
        format({ $0.addAttribute(.foregroundColor, value: color, range: $1) }, typing: { $0[.foregroundColor] = color })
    }
    func setHighlight(_ swatch: Swatch?) {
        format({ storage, range in
            if let swatch { storage.addAttribute(.backgroundColor, value: swatch.highlight, range: range) }
            else { storage.removeAttribute(.backgroundColor, range: range) }
        }, typing: { $0[.backgroundColor] = swatch?.highlight })
    }
    func setParagraph(_ change: @escaping (NSMutableParagraphStyle) -> Void) {
        let base = editor?.defaultParagraphStyle ?? .default
        format(paragraphs: true, { storage, range in
            storage.enumerateAttribute(.paragraphStyle, in: range) { value, subrange, _ in
                let style = ((value as? NSParagraphStyle) ?? base).mutableCopy() as! NSMutableParagraphStyle
                change(style); storage.addAttribute(.paragraphStyle, value: style, range: subrange)
            }
        }, typing: { attributes in
            let style = ((attributes[.paragraphStyle] as? NSParagraphStyle) ?? base).mutableCopy() as! NSMutableParagraphStyle
            change(style); attributes[.paragraphStyle] = style
        })
    }
    func setAlignment(_ alignment: NSTextAlignment) { setParagraph { $0.alignment = alignment } }
    func setSpacing(_ multiple: CGFloat) { setParagraph { $0.lineHeightMultiple = multiple } }
    func clearFormatting() {
        let paragraph = editor?.defaultParagraphStyle ?? .default
        let plain: [NSAttributedString.Key: Any] = [.font: Self.defaultFont, .foregroundColor: NSColor.labelColor, .paragraphStyle: paragraph]
        format({ storage, range in storage.setAttributes(plain, range: range) }, typing: { $0 = plain })
    }

    func refreshSelection() {
        guard let editor, let storage = editor.textStorage else { return }
        let selection = editor.selectedRange()
        let attributes = selection.length > 0 && selection.location < storage.length
            ? storage.attributes(at: selection.location, effectiveRange: nil) : editor.typingAttributes
        let font = attributes[.font] as? NSFont ?? Self.defaultFont
        let paragraph = attributes[.paragraphStyle] as? NSParagraphStyle ?? editor.defaultParagraphStyle ?? .default
        let traits = font.fontDescriptor.symbolicTraits
        let next = FormatState(style: TextStyle.of(font), family: FontChoice.of(font).name, size: font.pointSize,
            bold: traits.contains(.bold), italic: traits.contains(.italic),
            underline: (attributes[.underlineStyle] as? Int ?? 0) != 0, strike: (attributes[.strikethroughStyle] as? Int ?? 0) != 0,
            alignment: paragraph.alignment, spacing: paragraph.lineHeightMultiple == 0 ? 1 : paragraph.lineHeightMultiple)
        if next != state { state = next }
    }
}

// MARK: Format bar

/// Docs-style formatting bar, grouped like Docs: history · style · font · size · marks · color ·
/// link · paragraph · lists · clear. Narrow windows move font and paragraph controls into "More".
struct FormatBar: View {
    @ObservedObject var commands: EditorCommands
    let addLink: () -> Void
    /// Fonts picked from "More Fonts…", newest first, shown at the top of the font menu.
    @AppStorage("recentFonts") private var recentFonts = ""
    @State private var choosingFont = false
    var body: some View {
        ViewThatFits(in: .horizontal) {
            bar(compact: false)
            bar(compact: true)
        }
        .sheet(isPresented: $choosingFont) {
            FontPicker { family in
                commands.setFamily(FontChoice(name: family, family: family, design: nil))
                let recent = [family] + recentFonts.split(separator: "\n").map(String.init).filter { $0 != family }
                recentFonts = recent.prefix(5).joined(separator: "\n")
            }
        }
    }
    private func bar(compact: Bool) -> some View {
        HStack(spacing: 2) {
            HeaderIcon(icon: "arrow.uturn.backward", help: "Undo (⌘Z)") { NSApp.sendAction(Selector(("undo:")), to: nil, from: nil) }
            HeaderIcon(icon: "arrow.uturn.forward", help: "Redo (⇧⌘Z)") { NSApp.sendAction(Selector(("redo:")), to: nil, from: nil) }
            BarDivider()
            BarPicker(title: commands.state.style.rawValue, width: 92) { close in stylePicker(close) }
            if !compact {
                BarDivider()
                BarPicker(title: commands.state.family, width: 88) { close in fontPicker(close) }
                BarDivider()
                sizeControl
            }
            BarDivider()
            HeaderIcon(icon: "bold", help: "Bold (⌘B)", active: commands.state.bold) { commands.style("bold") }
            HeaderIcon(icon: "italic", help: "Italic (⌘I)", active: commands.state.italic) { commands.style("italic") }
            HeaderIcon(icon: "underline", help: "Underline (⌘U)", active: commands.state.underline) { commands.style("underline") }
            HeaderIcon(icon: "strikethrough", help: "Strikethrough", active: commands.state.strike) { commands.style("strike") }
            SwatchButton(kind: .text, commands: commands)
            SwatchButton(kind: .highlight, commands: commands)
            BarDivider()
            HeaderIcon(icon: "link", help: "Link (⌘K)", action: addLink)
            if !compact {
                BarMenu(icon: alignmentIcon(commands.state.alignment), help: "Align") { alignmentItems }
                BarMenu(icon: "arrow.up.and.down.text.horizontal", help: "Line Spacing") { spacingItems }
            }
            BarDivider()
            HeaderIcon(icon: "checklist", help: "Checklist") { commands.style("check") }
            HeaderIcon(icon: "list.bullet", help: "Bulleted List") { commands.style("bullet") }
            HeaderIcon(icon: "list.number", help: "Numbered List") { commands.style("number") }
            BarDivider()
            if compact {
                BarMenu(icon: "ellipsis", help: "More formatting") {
                    Menu("Font") { fontItems }
                    Menu("Size") { sizeItems }
                    Menu("Align") { alignmentItems }
                    Menu("Line Spacing") { spacingItems }
                    Divider()
                    Button("Clear Formatting") { commands.clearFormatting() }
                }
            }
            Spacer(minLength: 0)
        }
    }

    @ViewBuilder var styleItems: some View {
        ForEach(TextStyle.allCases) { style in
            Button(style.rawValue) { commands.setStyle(style) }
        }
    }
    /// Styles drawn as they look, as in Docs.
    private func stylePicker(_ close: @escaping () -> Void) -> some View {
        ForEach(TextStyle.allCases) { style in
            PickerRow(selected: commands.state.style == style, action: { commands.setStyle(style); close() }) {
                Text(style.rawValue).font(style.preview).foregroundStyle(Theme.text)
            }
        }
    }
    /// Fonts drawn in their own face: recent picks, the short list, then every installed font.
    @ViewBuilder private func fontPicker(_ close: @escaping () -> Void) -> some View {
        let recent = recentFonts.split(separator: "\n").map(String.init)
            .filter { family in NSFontManager.shared.availableFontFamilies.contains(family) && !FontChoice.all.contains { $0.family == family } }
        let row = { (choice: FontChoice) in
            PickerRow(selected: commands.state.family == choice.name, action: { commands.setFamily(choice); close() }) {
                Text(choice.name).font(choice.preview).foregroundStyle(Theme.text)
            }
        }
        if !recent.isEmpty {
            PickerHeading("Recent")
            ForEach(recent, id: \.self) { family in row(FontChoice(name: family, family: family, design: nil)) }
            Divider().padding(.vertical, 4)
        }
        ForEach(FontChoice.all) { row($0) }
        Divider().padding(.vertical, 4)
        PickerRow(selected: false, action: { close(); choosingFont = true }) {
            Label("More Fonts…", systemImage: "textformat").font(Theme.sans(13)).foregroundStyle(Theme.text)
        }
    }
    @ViewBuilder var fontItems: some View {
        let recent = recentFonts.split(separator: "\n").map(String.init)
            .filter { family in NSFontManager.shared.availableFontFamilies.contains(family) && !FontChoice.all.contains { $0.family == family } }
        if !recent.isEmpty {
            Section("Recent") {
                ForEach(recent, id: \.self) { family in Button(family) { commands.setFamily(FontChoice(name: family, family: family, design: nil)) } }
            }
        }
        Section {
            ForEach(FontChoice.all) { choice in Button(choice.name) { commands.setFamily(choice) } }
        }
        Divider()
        Button("More Fonts…") { choosingFont = true }
    }
    @ViewBuilder var sizeItems: some View {
        ForEach([10, 12, 14, 15, 17, 20, 24, 30, 36, 48], id: \.self) { size in
            Button("\(size)") { commands.setSize(CGFloat(size)) }
        }
    }
    @ViewBuilder var alignmentItems: some View {
        Button("Left") { commands.setAlignment(.left) }
        Button("Center") { commands.setAlignment(.center) }
        Button("Right") { commands.setAlignment(.right) }
        Button("Justify") { commands.setAlignment(.justified) }
    }
    @ViewBuilder var spacingItems: some View {
        Button("Single") { commands.setSpacing(1) }
        Button("1.15") { commands.setSpacing(1.15) }
        Button("1.3 (default)") { commands.setSpacing(1.3) }
        Button("1.5") { commands.setSpacing(1.5) }
        Button("Double") { commands.setSpacing(2) }
    }
    /// − size + , as in Docs.
    private var sizeControl: some View {
        HStack(spacing: 0) {
            HeaderIcon(icon: "minus", help: "Decrease Size") { commands.setSize(commands.state.size - 1) }
            Menu { sizeItems } label: {
                Text("\(Int(commands.state.size.rounded()))").font(Theme.sans(13)).monospacedDigit().foregroundStyle(Theme.text)
                    .frame(width: 30, height: 24)
            }
            .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
            .overlay(RoundedRectangle(cornerRadius: 4).strokeBorder(Theme.divider))
            HeaderIcon(icon: "plus", help: "Increase Size") { commands.setSize(commands.state.size + 1) }
        }
    }
    private func alignmentIcon(_ alignment: NSTextAlignment) -> String {
        switch alignment {
        case .center: return "text.aligncenter"
        case .right: return "text.alignright"
        case .justified: return "text.justify"
        default: return "text.alignleft"
        }
    }
}

/// A compact dropdown in the format bar: a text label or an icon, with a small chevron.
struct BarMenu<Content: View>: View {
    var title: String?
    var icon: String?
    var help = ""
    var width: CGFloat?
    @ViewBuilder var content: Content
    @State private var hovering = false
    init(title: String, width: CGFloat? = nil, @ViewBuilder content: () -> Content) {
        self.title = title; self.width = width; self.content = content()
    }
    init(icon: String, help: String, @ViewBuilder content: () -> Content) {
        self.icon = icon; self.help = help; self.content = content()
    }
    var body: some View {
        Menu { content } label: {
            // One Text, so macOS keeps the chevron after the label instead of moving the image first.
            let chevron = Text(" ") + Text(Image(systemName: "chevron.down")).font(Theme.sans(8, .bold)).foregroundColor(Theme.secondary)
            let label = title.map { Text($0) } ?? Text(Image(systemName: icon ?? "")).font(Theme.sans(13.5, .medium))
            (label + chevron).lineLimit(1).frame(width: width.map { $0 + 14 }, alignment: .leading)
                .font(Theme.sans(13)).foregroundStyle(Theme.text)
        }
        .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
        .padding(.horizontal, 7).frame(height: 28)
        .background(hovering ? Theme.hover : Color.clear, in: RoundedRectangle(cornerRadius: 5))
        .onHover { hovering = $0 }.help(help)
    }
}

/// Text color ("A" with a color bar) or highlight, each opening a small swatch grid.
struct SwatchButton: View {
    enum Kind { case text, highlight }
    let kind: Kind
    @ObservedObject var commands: EditorCommands
    @State private var open = false
    @State private var hovering = false
    var body: some View {
        Button { open = true } label: {
            Group {
                if kind == .text {
                    VStack(spacing: 1) {
                        Text("A").font(.system(size: 14, weight: .semibold)).foregroundStyle(Theme.text)
                        Capsule().fill(Theme.text).frame(width: 14, height: 2.5)
                    }
                } else {
                    Image(systemName: "highlighter").font(.system(size: 13.5, weight: .medium)).foregroundStyle(Theme.text)
                }
            }
            .frame(width: 30, height: 28)
            .background(hovering || open ? Theme.hover : Color.clear, in: RoundedRectangle(cornerRadius: 5))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain).onHover { hovering = $0 }
        .help(kind == .text ? "Text Color" : "Highlight")
        .popover(isPresented: $open, arrowEdge: .bottom) {
            VStack(alignment: .leading, spacing: 10) {
                Text(kind == .text ? "Text Color" : "Highlight").font(Theme.sans(12, .medium)).foregroundStyle(Theme.secondary)
                LazyVGrid(columns: Array(repeating: GridItem(.fixed(24), spacing: 8), count: 5), spacing: 8) {
                    swatch(nil)
                    ForEach(Swatch.allCases) { swatch($0) }
                }
            }
            .padding(14)
        }
    }
    private func swatch(_ value: Swatch?) -> some View {
        Button {
            if kind == .text { commands.setColor(value) } else { commands.setHighlight(value) }
            open = false
        } label: {
            ZStack {
                if let value {
                    if kind == .text {
                        Text("A").font(.system(size: 14, weight: .semibold)).foregroundStyle(Color(nsColor: value.color))
                    } else {
                        RoundedRectangle(cornerRadius: 4).fill(Color(nsColor: value.highlight))
                    }
                } else {
                    Image(systemName: kind == .text ? "textformat" : "nosign").font(.system(size: 11)).foregroundStyle(Theme.secondary)
                }
            }
            .frame(width: 24, height: 24)
            .overlay(RoundedRectangle(cornerRadius: 4).strokeBorder(Theme.divider))
        }
        .buttonStyle(.plain).help(value.map { $0.rawValue.capitalized } ?? "Default")
    }
}

/// Every font family on this Mac, searchable, each name shown in its own face.
struct FontPicker: View {
    let choose: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var search = ""
    @State private var hovered: String?
    // Helvetica Neue is left out: RTF stores the system font under that name, so it reads back as Sans.
    private static let families = NSFontManager.shared.availableFontFamilies.filter { !$0.hasPrefix(".") && $0 != "Helvetica Neue" }.sorted()
    private var matches: [String] { search.isEmpty ? Self.families : Self.families.filter { $0.localizedCaseInsensitiveContains(search) } }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Fonts").font(Theme.heading(15)).tracking(-0.1).foregroundStyle(Theme.text)
                Spacer()
                Text("\(matches.count) of \(Self.families.count)").font(Theme.sans(12)).foregroundStyle(Theme.tertiary)
            }
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").font(.system(size: 12)).foregroundStyle(Theme.secondary)
                TextField("Search fonts", text: $search).textFieldStyle(.plain).font(Theme.sans(13.5))
            }
            .padding(.horizontal, 8).frame(height: 30)
            .background(Theme.hover.opacity(0.6), in: RoundedRectangle(cornerRadius: 6))
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 1) {
                    ForEach(matches, id: \.self) { family in
                        Button { choose(family); dismiss() } label: {
                            Text(family).font(.custom(family, size: 16)).foregroundStyle(Theme.text).lineLimit(1)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.horizontal, 8).frame(height: 32)
                                .background(hovered == family ? Theme.hover : Color.clear, in: RoundedRectangle(cornerRadius: 5))
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain).onHover { hovered = $0 ? family : (hovered == family ? nil : hovered) }
                    }
                }
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction).humaButton()
            }
        }
        .padding(20).frame(width: 380, height: 480).humaSheetHeader().presentationBackground(Theme.page)
    }
}

/// Format-bar control that opens a popover list, so options can be drawn as they look
/// (menus can't show fonts). Looks like BarMenu.
struct BarPicker<Content: View>: View {
    let title: String
    var width: CGFloat?
    @ViewBuilder var content: (_ close: @escaping () -> Void) -> Content
    @State private var open = false
    @State private var hovering = false
    var body: some View {
        Button { open.toggle() } label: {
            (Text(title) + Text(" ") + Text(Image(systemName: "chevron.down")).font(Theme.sans(8, .bold)).foregroundColor(Theme.secondary))
                .lineLimit(1).frame(width: width.map { $0 + 14 }, alignment: .leading)
                .font(Theme.sans(13)).foregroundStyle(Theme.text)
                .padding(.horizontal, 7).frame(height: 28)
                .background(hovering || open ? Theme.hover : Color.clear, in: RoundedRectangle(cornerRadius: 5))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain).onHover { hovering = $0 }
        .popover(isPresented: $open, arrowEdge: .bottom) {
            ScrollView {
                VStack(alignment: .leading, spacing: 1) { content { open = false } }.padding(6)
            }
            .frame(width: 230).frame(maxHeight: 420).fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// One row in a picker popover: hover highlight and a check on the current choice.
struct PickerRow<Label: View>: View {
    let selected: Bool
    let action: () -> Void
    @ViewBuilder var label: Label
    @State private var hovering = false
    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: "checkmark").font(.system(size: 11, weight: .semibold)).foregroundStyle(Theme.accent)
                    .opacity(selected ? 1 : 0).frame(width: 14)
                label.lineLimit(1)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 8).padding(.vertical, 6)
            .background(hovering ? Theme.hover : Color.clear, in: RoundedRectangle(cornerRadius: 6))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain).onHover { hovering = $0 }
    }
}

struct PickerHeading: View {
    let title: String
    init(_ title: String) { self.title = title }
    var body: some View {
        Text(title).font(Theme.sans(11.5, .medium)).foregroundStyle(Theme.tertiary).padding(.horizontal, 30).padding(.top, 4).padding(.bottom, 2)
    }
}
