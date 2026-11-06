import SwiftUI

/// A row of small blocks, filled left to right: ▮▮▮▮▯▯▯. The block being worked on pulses.
struct SegmentedProgress: View {
    let fraction: Double
    var tint: Color = Theme.accent
    var active = false
    var segments = 18
    var body: some View {
        TimelineView(.animation(minimumInterval: 1 / 20, paused: !active)) { context in
            let pulse = 0.45 + 0.4 * (1 + sin(context.date.timeIntervalSinceReferenceDate * 4)) / 2
            HStack(spacing: 2.5) {
                ForEach(0..<segments, id: \.self) { index in
                    let fill = min(1, max(0, fraction * Double(segments) - Double(index)))
                    let leading = active && fill < 1 && (fill > 0 || index == Int(fraction * Double(segments)))
                    RoundedRectangle(cornerRadius: 1.5).fill(Theme.divider)
                        .overlay(alignment: .leading) {
                            GeometryReader { geometry in
                                RoundedRectangle(cornerRadius: 1.5).fill(tint).frame(width: geometry.size.width * max(fill, leading ? 1 : 0))
                            }
                        }
                        .opacity(leading ? pulse : 1)
                        .frame(width: 7, height: 11)
                }
            }
        }
        .accessibilityElement().accessibilityLabel("Progress").accessibilityValue("\(Int(fraction * 100)) percent")
    }
}

/// A coral recording dot that breathes, with a soft glow and an expanding ring.
struct RecordingDot: View {
    var body: some View {
        TimelineView(.animation(minimumInterval: 1 / 30)) { context in
            let phase = context.date.timeIntervalSinceReferenceDate.truncatingRemainder(dividingBy: 1.6) / 1.6
            let breathe = 0.5 + 0.5 * sin(phase * 2 * .pi)
            ZStack {
                Circle().stroke(Theme.danger.opacity(0.5 * (1 - phase)), lineWidth: 1.5).frame(width: 8 + 12 * phase, height: 8 + 12 * phase)
                Circle().fill(Theme.danger).frame(width: 8, height: 8)
                    .shadow(color: Theme.danger.opacity(0.4 + 0.5 * breathe), radius: 3 + 4 * breathe)
            }
            .frame(width: 20, height: 20)
        }
        .accessibilityLabel("Recording")
    }
}

/// Bottom status bar: what is happening on the left, progress and length on the right.
struct StatusBar<Leading: View, Trailing: View>: View {
    var highlighted = false
    var recording = false
    @ViewBuilder var leading: Leading
    @ViewBuilder var trailing: Trailing
    var body: some View {
        VStack(spacing: 0) {
            Rectangle().fill(Theme.divider).frame(height: 1)
            HStack(spacing: 10) {
                leading
                Spacer(minLength: 12)
                trailing
            }
            .monoLabel(11).foregroundStyle(Theme.secondary)
            .padding(.horizontal, 18).frame(height: 36)
            .background(highlighted ? Theme.tag(.blue).0 : recording ? Theme.tag(.red).0.opacity(0.45) : Theme.page)
            .overlay(alignment: .top) {
                if recording { LinearGradient(colors: [Theme.danger.opacity(0.35), .clear], startPoint: .top, endPoint: .bottom).frame(height: 6).allowsHitTesting(false) }
            }
        }
    }
}
