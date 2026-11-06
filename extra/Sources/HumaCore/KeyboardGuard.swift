import Foundation
import IOKit

/// Which keyboards are plugged in, read from the I/O registry, so no Input Monitoring permission is needed.
/// Huma counts typing fully only from the Mac's own keyboard or an Apple keyboard (and security keys). While any other keyboard is
/// plugged in, including programmable boards and virtual keyboards that can type for you, typing is labelled "typing-external" and
/// counts for less in the page's score (HumaScore); `blocked` names that keyboard.
/// macOS doesn't say which keyboard sent a key, so the whole Mac is checked, not each key.
@MainActor public final class KeyboardGuard {
    public struct Keyboard: Equatable, Sendable {
        public var name: String
        public var builtIn: Bool
        public var vendor: Int
        /// How it's connected ("USB", "Bluetooth"…). Virtual keyboards made by software often have none.
        public var transport: String? = nil
        /// The DriverKit driver behind it, when there is one ("com.apple.driverkit…" for Apple's own).
        public var driver: String? = nil
        /// A vendor ID is whatever the device says, and virtual keyboards can say Apple's (Karabiner-Elements does).
        /// So an Apple ID counts only from a connected device that no third-party driver makes.
        public var allowed: Bool {
            builtIn || (KeyboardGuard.allowedVendors.contains(vendor) && transport != nil && driver.map { $0.hasPrefix("com.apple.") } ?? true)
        }
    }
    /// Apple's USB (0x05AC) and Bluetooth (0x004C) vendor IDs, and Yubico (0x1050): a security key
    /// shows up as a keyboard but can only type one short code, never a page.
    nonisolated static let allowedVendors: Set<Int> = [0x05AC, 0x004C, 0x1050]
    public static let shared = KeyboardGuard()
    /// Posted when the keyboard Huma counts for less changes (one plugged in or removed).
    public static let changed = Notification.Name("HumaKeyboardsChanged")

    public private(set) var keyboards: [Keyboard] = []
    /// The first keyboard Huma won't record from, or nil when every keyboard is allowed.
    public var blocked: Keyboard? { keyboards.first { !$0.allowed } }
    private var port: IONotificationPortRef?

    private init() {
        keyboards = Self.scan()
        watch()
    }

    public static func scan() -> [Keyboard] {
        var iterator: io_iterator_t = 0
        guard IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOHIDDevice"), &iterator) == KERN_SUCCESS else { return [] }
        defer { IOObjectRelease(iterator) }
        var found: [Keyboard] = []
        while case let service = IOIteratorNext(iterator), service != 0 {
            defer { IOObjectRelease(service) }
            func value(_ key: String) -> Any? { IORegistryEntryCreateCFProperty(service, key as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() }
            let pairs = (value("DeviceUsagePairs") as? [[String: Any]]) ?? []
            let keyboard = pairs.contains { ($0["DeviceUsagePage"] as? Int) == 1 && ($0["DeviceUsage"] as? Int) == 6 }
                || ((value("PrimaryUsagePage") as? Int) == 1 && (value("PrimaryUsage") as? Int) == 6)
            guard keyboard else { continue }
            found.append(Keyboard(name: (value("Product") as? String) ?? "A keyboard", builtIn: (value("Built-In") as? Bool) ?? false,
                                  vendor: (value("VendorID") as? Int) ?? 0, transport: value("Transport") as? String,
                                  driver: value("IOUserServerName") as? String))
        }
        return found
    }

    /// Rescans the moment any HID device is plugged in or removed, so there's no window to type from a new one.
    private func watch() {
        guard let port = IONotificationPortCreate(kIOMainPortDefault) else { return }
        self.port = port
        CFRunLoopAddSource(CFRunLoopGetMain(), IONotificationPortGetRunLoopSource(port).takeUnretainedValue(), .commonModes)
        let callback: IOServiceMatchingCallback = { refcon, iterator in
            while case let service = IOIteratorNext(iterator), service != 0 { IOObjectRelease(service) }
            guard let refcon else { return }
            let guardian = Unmanaged<KeyboardGuard>.fromOpaque(refcon).takeUnretainedValue()
            MainActor.assumeIsolated {
                let before = guardian.blocked
                guardian.keyboards = KeyboardGuard.scan()
                if guardian.blocked != before { NotificationCenter.default.post(name: KeyboardGuard.changed, object: guardian) }
            }
        }
        let refcon = Unmanaged.passUnretained(self).toOpaque()
        for kind in [kIOFirstMatchNotification, kIOTerminatedNotification] {
            var iterator: io_iterator_t = 0
            if IOServiceAddMatchingNotification(port, kind, IOServiceMatching("IOHIDDevice"), callback, refcon, &iterator) == KERN_SUCCESS {
                // Arms the notification; the devices already present were counted by the first scan.
                while case let service = IOIteratorNext(iterator), service != 0 { IOObjectRelease(service) }
            }
        }
    }
}
