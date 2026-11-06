import XCTest
@testable import HumaCore

/// Which keyboards count fully. Properties are as the I/O registry reports them: this Mac's own keyboard, and
/// Karabiner's virtual keyboard from its source (pqrs-org/Karabiner-DriverKit-VirtualHIDDevice).
final class KeyboardGuardTests: XCTestCase {
    typealias Keyboard = KeyboardGuard.Keyboard

    func testTheMacsOwnAndApplesKeyboardsCountFully() {
        XCTAssertTrue(Keyboard(name: "Apple Internal Keyboard / Trackpad", builtIn: true, vendor: 0, transport: "FIFO").allowed)
        XCTAssertTrue(Keyboard(name: "Magic Keyboard", builtIn: false, vendor: 0x004C, transport: "Bluetooth").allowed)
        XCTAssertTrue(Keyboard(name: "Magic Keyboard", builtIn: false, vendor: 0x05AC, transport: "USB",
                               driver: "com.apple.driverkit.AppleUserHIDDrivers").allowed)
        XCTAssertTrue(Keyboard(name: "YubiKey OTP+FIDO+CCID", builtIn: false, vendor: 0x1050, transport: "USB").allowed)
    }

    func testVirtualKeyboardsDontCountFullyEvenWithApplesID() {
        // Karabiner's own ID, and Apple's, which Karabiner-Elements gives it.
        for vendor in [0x16C0, 0x05AC] {
            XCTAssertFalse(Keyboard(name: "Karabiner DriverKit VirtualHIDKeyboard 6.4.0", builtIn: false, vendor: vendor,
                                    driver: "org.pqrs.Karabiner-DriverKit-VirtualHIDDevice").allowed)
        }
        // A third-party driver that does name a connection.
        XCTAssertFalse(Keyboard(name: "Keyboard", builtIn: false, vendor: 0x05AC, transport: "USB", driver: "com.example.typer").allowed)
        XCTAssertFalse(Keyboard(name: "Pro Micro", builtIn: false, vendor: 0x2341, transport: "USB").allowed)
    }

    /// The limit, kept visible: a USB device that copies an Apple keyboard's ID can't be told apart from one.
    func testAUSBDeviceThatCopiesApplesIDStillPasses() {
        XCTAssertTrue(Keyboard(name: "Keyboard", builtIn: false, vendor: 0x05AC, transport: "USB").allowed)
    }
}
