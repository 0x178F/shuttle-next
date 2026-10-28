import AppKit

enum ShuttleIcon {
    static func drawMark(in rect: NSRect, ink: NSColor, node: NSColor) {
        func point(_ x: CGFloat, _ y: CGFloat) -> NSPoint {
            NSPoint(x: rect.minX + x * rect.width / 32, y: rect.minY + y * rect.height / 24)
        }
        let strokes = NSBezierPath()
        strokes.lineWidth = rect.width * 2.8 / 32
        strokes.lineCapStyle = .round
        strokes.lineJoinStyle = .round
        strokes.move(to: point(3, 20))
        strokes.line(to: point(12, 12))
        strokes.line(to: point(3, 4))
        strokes.move(to: point(18, 4))
        strokes.line(to: point(24, 4))
        ink.setStroke()
        strokes.stroke()
        let center = point(30, 4)
        let radius = rect.width * 2.5 / 32
        node.setFill()
        NSBezierPath(ovalIn: NSRect(x: center.x - radius, y: center.y - radius, width: radius * 2, height: radius * 2)).fill()
    }

    static func statusImage() -> NSImage {
        let image = NSImage(size: NSSize(width: 20, height: 18), flipped: false) { _ in
            drawMark(in: NSRect(x: 1, y: 2, width: 18, height: 13.5), ink: .black, node: .black)
            return true
        }
        image.isTemplate = true
        return image
    }
}
