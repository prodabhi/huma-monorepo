import SwiftUI
import HumaCore

/// The Huma score as one row: the number, and what made it (HumaScore).
struct ScoreRow: View {
    let score: HumaScore
    var note: String?
    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            ZStack {
                Circle().stroke(Theme.divider, lineWidth: 4)
                Circle().trim(from: 0, to: CGFloat(score.value) / 100).stroke(Self.tint(score.value), style: StrokeStyle(lineWidth: 4, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                Text("\(score.value)").font(Theme.heading(17)).monospacedDigit().foregroundStyle(Theme.text)
            }
            .frame(width: 46, height: 46)
            VStack(alignment: .leading, spacing: 3) {
                Text("Huma Score").font(Theme.heading(13)).tracking(-0.1).foregroundStyle(Theme.text)
                Text(Self.parts(score)).font(Theme.sans(12)).foregroundStyle(Theme.secondary).fixedSize(horizontal: false, vertical: true)
                if let note { Text(note).font(Theme.sans(12)).foregroundStyle(Theme.tertiary) }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .humaCard(14)
        .help("Typed by hand: \(score.points.typed) of 70 points. Typing checks: \(score.points.checks) of 20. Touch ID: \(score.points.touch) of 10.")
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Huma Score \(score.value) out of 100. \(Self.parts(score))")
    }
    /// "100% typed · 7 of 7 typing checks · Touch ID 2 of 2", as readers see it.
    static func parts(_ score: HumaScore) -> String { score.line }
    /// Green when it's high; otherwise amber, as on the shared page. A lower score isn't an error.
    static func tint(_ value: Int) -> Color { value >= 85 ? Theme.success : Theme.warning }
}
