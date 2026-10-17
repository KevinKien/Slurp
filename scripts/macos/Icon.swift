import AppKit

guard CommandLine.arguments.count == 2 else { fatalError("Usage: icon <output.png>") }
let size = 1024
let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
NSColor(calibratedRed: 0.28, green: 0.83, blue: 0.64, alpha: 1).setFill()
NSBezierPath(roundedRect: NSRect(x: 64, y: 64, width: 896, height: 896), xRadius: 160, yRadius: 160).fill()
NSColor(calibratedRed: 0.04, green: 0.13, blue: 0.10, alpha: 1).setStroke()
let path = NSBezierPath()
path.lineWidth = 58
path.lineCapStyle = .round
path.lineJoinStyle = .round
for (index, point) in [(2.0,12.0),(5.0,12.0),(9.0,3.0),(14.5,21.0),(18.0,12.0),(22.0,12.0)].enumerated() {
    let point = NSPoint(x: 176 + point.0 / 24 * 672, y: 176 + (24 - point.1) / 24 * 672)
    if index == 0 { path.move(to: point) } else { path.line(to: point) }
}
path.stroke()
NSGraphicsContext.restoreGraphicsState()
try bitmap.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
