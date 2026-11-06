import AppKit
import JavaScriptCore
import SwiftUI

/// The writer's name and face, shown in the sidebar and on every page they share ("Written by …").
/// Faces are DiceBear "Dylan" drawings made from a short seed, drawn on this Mac the same way huma.social draws
/// them for readers; only the seed is kept or sent.
@MainActor final class Profile: ObservableObject {
    static let shared = Profile()
    @Published var name = UserDefaults.standard.string(forKey: "profileName") ?? "" {
        didSet { UserDefaults.standard.set(name, forKey: "profileName") }
    }
    @Published var avatar = UserDefaults.standard.string(forKey: "profileAvatar") ?? Profile.newSeed() {
        didSet { UserDefaults.standard.set(avatar, forKey: "profileAvatar") }
    }
    private init() { UserDefaults.standard.set(avatar, forKey: "profileAvatar") }

    /// What a shared page shows, or nil until a name is chosen. Cleaned the way huma.social checks it
    /// (publication-contract.mjs writerProfile): no control or format characters, at most 40 code points.
    var shared: [String: String]? {
        let scalars = name.precomposedStringWithCanonicalMapping.unicodeScalars
            .filter { ![.control, .format, .privateUse, .surrogate, .unassigned].contains($0.properties.generalCategory) }
        let clean = String(String.UnicodeScalarView(scalars)).split(whereSeparator: \.isWhitespace).joined(separator: " ")
        return clean.isEmpty ? nil : ["name": String(String.UnicodeScalarView(clean.unicodeScalars.prefix(40))), "avatar": avatar]
    }
    static func newSeed() -> String {
        let letters = Array("abcdefghijkmnpqrstuvwxyz23456789")
        return String((0..<10).map { _ in letters.randomElement()! })
    }
}

/// A face for a seed, drawn on this Mac. Until it's drawn, a soft circle.
struct FaceView: View {
    let seed: String
    var size: CGFloat = 28
    @State private var image: NSImage?
    var body: some View {
        ZStack {
            Circle().fill(Theme.callout)
            if let image { Image(nsImage: image).resizable().scaledToFill() }
        }
        .frame(width: size, height: size).clipShape(Circle())
        .overlay(Circle().strokeBorder(Theme.divider))
        .task(id: seed) { image = await FaceCache.image(seed) }
    }
}

@MainActor enum FaceCache {
    private static var memory: [String: NSImage] = [:]
    private static var folder: URL {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent(Bundle.main.bundleIdentifier ?? "dev.swayam.huma").appendingPathComponent("Faces")
    }
    static func image(_ seed: String) async -> NSImage? {
        guard seed.range(of: #"^[A-Za-z0-9_-]{1,32}$"#, options: .regularExpression) != nil else { return nil }
        if let image = memory[seed] { return image }
        if let data = FaceDrawing.svg(seed), let image = NSImage(data: data) { memory[seed] = image; return image }
        // Without the bundled script (a bare `swift run`), ask huma.social and keep its answer.
        let file = folder.appendingPathComponent(seed + ".svg")
        if let data = try? Data(contentsOf: file), let image = NSImage(data: data) { memory[seed] = image; return image }
        let host = UserDefaults.standard.string(forKey: "registryURL") ?? "https://api.huma.social"
        guard let url = URL(string: host + "/avatar/" + seed + ".svg"),
              let (data, response) = try? await URLSession.shared.data(from: url),
              (response as? HTTPURLResponse)?.statusCode == 200, data.count < 64 * 1024,
              let image = NSImage(data: data) else { return nil }
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        try? data.write(to: file, options: .atomic)
        memory[seed] = image
        return image
    }
}

/// The site's face code (DiceBear and its Dylan style, built from frontend/faces/entry.mjs into extra/Resources/Faces.js),
/// run in JavaScriptCore, so a face is the same SVG a reader's page gets from huma.social for that seed.
@MainActor enum FaceDrawing {
    private static let draw: JSValue? = {
        guard let url = Bundle.main.url(forResource: "Faces", withExtension: "js"),
              let script = try? String(contentsOf: url, encoding: .utf8), let context = JSContext() else { return nil }
        context.evaluateScript(script, withSourceURL: url)
        guard context.exception == nil, let draw = context.objectForKeyedSubscript("humaFace"), !draw.isUndefined else { return nil }
        return draw
    }()
    static func svg(_ seed: String) -> Data? {
        guard let value = draw?.call(withArguments: [seed]), value.isString, let text = value.toString() else { return nil }
        return Data(text.utf8)
    }
}

/// A name field and a grid of faces to pick from. Shuffle draws new faces; the one you pick is kept.
/// Used by the profile editor and by onboarding.
struct ProfileFields: View {
    @Binding var name: String
    @Binding var picked: String
    var faceSize: CGFloat = 56
    @State private var choices: [String] = []
    @FocusState private var nameFocused: Bool
    var body: some View {
        VStack(spacing: 14) {
            // A name is needed: as in Mac setup screens, the field starts focused and Continue (or Save) stays
            // unavailable until it's filled, rather than a "required" label.
            TextField("Your name", text: $name).textFieldStyle(.plain).font(Theme.sans(14)).focused($nameFocused)
                .padding(.horizontal, 12).frame(height: 38)
                .background(Theme.callout, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                .onChange(of: name) { _, value in if value.count > 40 { name = String(value.prefix(40)) } }
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("Face").monoLabel(11).foregroundStyle(Theme.secondary)
                    Spacer()
                    Button { withAnimation(.spring(duration: 0.35)) { shuffle() } } label: { Label("Shuffle", systemImage: "shuffle") }
                        .humaButton(small: true)
                }
                LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 10), count: 4), spacing: 10) {
                    ForEach(choices, id: \.self) { seed in
                        Button { picked = seed } label: {
                            FaceView(seed: seed, size: faceSize)
                                .overlay(Circle().strokeBorder(seed == picked ? Theme.accent : .clear, lineWidth: 3).padding(-4))
                        }
                        .buttonStyle(.plain).accessibilityLabel(seed == picked ? "Face, selected" : "Face")
                        .accessibilityAddTraits(seed == picked ? .isSelected : [])
                    }
                }
            }
            .padding(14).humaCard(14)
        }
        .onAppear { if choices.isEmpty { shuffle() }; if name.isEmpty { nameFocused = true } }
    }
    private func shuffle() { choices = [picked] + (0..<7).map { _ in Profile.newSeed() } }
}

/// Choose a name and a face, then save or cancel.
struct ProfileEditor: View {
    @ObservedObject var profile = Profile.shared
    let done: () -> Void
    @State private var name = Profile.shared.name
    @State private var picked = Profile.shared.avatar
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .bottom) {
                SheetTitle(title: "Your Profile", detail: "Shown on pages you share.")
                FaceView(seed: picked, size: 64)
            }
            ProfileFields(name: $name, picked: $picked).padding(.top, 22)
            HStack(spacing: 8) {
                Spacer()
                Button("Cancel", action: done).humaButton().keyboardShortcut(.cancelAction)
                Button("Save") { profile.name = name.trimmingCharacters(in: .whitespacesAndNewlines); profile.avatar = picked; done() }
                    .humaButton(.primary).keyboardShortcut(.defaultAction)
                    .disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .padding(.top, 20)
        }
        .padding(28).frame(width: 420).humaSheetHeader().presentationBackground(Theme.page)
    }
}
