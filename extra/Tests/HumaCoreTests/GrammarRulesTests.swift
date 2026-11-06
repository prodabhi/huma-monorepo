import Foundation
import XCTest
@testable import HumaCore

final class GrammarRulesTests: XCTestCase {
    func testHumaFindsALowercaseIRepeatedWordsAndSentencesWithoutACapital() {
        let text = "hey this is swayam and i am really excited. this this is it, i.e. done. I'm sure i'll go. Check https://huma.social. iPhone sales rose."
        let found = GrammarRules.issues(in: text).map { (($0.original, $0.suggestion)) }
        XCTAssertTrue(found.contains { $0 == ("hey", "Hey") })
        XCTAssertTrue(found.contains { $0 == ("this this", "this") })
        XCTAssertTrue(found.contains { $0 == ("this", "This") })
        XCTAssertEqual(found.filter { $0 == ("i", "I") }.count, 2) // "i am" and "i'll", not "i.e."
        XCTAssertFalse(found.contains { $0.0 == "iPhone" || $0.0 == "https" || $0.0.lowercased() == "i'm" })
        XCTAssertTrue(GrammarRules.issues(in: "I know that that works, and it had had an effect.").isEmpty)
    }
    func testOnlyRealFixesFromTheModelAreKept() {
        XCTAssertTrue(GrammarRules.isFix(original: "He go", suggestion: "He goes"))
        XCTAssertTrue(GrammarRules.isFix(original: "Their", suggestion: "They're"))
        XCTAssertTrue(GrammarRules.isFix(original: "swayam", suggestion: "Swayam"))
        XCTAssertFalse(GrammarRules.isFix(original: "I'm", suggestion: "I am"))
        XCTAssertFalse(GrammarRules.isFix(original: "don't", suggestion: "do not"))
        XCTAssertFalse(GrammarRules.isFix(original: "it.", suggestion: "it"))
        XCTAssertFalse(GrammarRules.isFix(original: "don't", suggestion: "does"))
        XCTAssertTrue(GrammarRules.isFix(original: "She don't", suggestion: "She doesn't"))
        XCTAssertFalse(GrammarRules.isFix(original: "The meeting went well.", suggestion: ""))
        XCTAssertFalse(GrammarRules.isFix(original: "everyone knows", suggestion: "everyone knows"))
        XCTAssertFalse(GrammarRules.isFix(original: String(repeating: "word ", count: 20), suggestion: "a rewrite"))
    }
    func testAFixIsPlacedInTheSentenceItCameFrom() {
        let text = "He go home. She go too."
        let sentences = GrammarRules.sentences(in: text)
        XCTAssertEqual(sentences.count, 2)
        XCTAssertEqual(GrammarRules.place("go", in: text, sentence: sentences[1]), NSRange(location: 16, length: 2))
        XCTAssertEqual(GrammarRules.place("she GO", in: text, sentence: sentences[1]), NSRange(location: 12, length: 6))
        XCTAssertNil(GrammarRules.place("went", in: text, sentence: sentences[0]))
    }
}
