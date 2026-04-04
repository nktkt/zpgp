//! OpenPGP packet parsing module.
//!
//! Re-exports all packet sub-modules for convenient access:
//!
//! ```
//! const packet = @import("packet/packet.zig");
//! const tag = packet.PacketTag.literal_data;
//! ```

pub const tags = @import("tags.zig");
pub const header = @import("header.zig");
pub const reader = @import("reader.zig");
pub const writer = @import("writer.zig");

pub const PacketTag = tags.PacketTag;
pub const PacketHeader = header.PacketHeader;
pub const Format = header.Format;
pub const BodyLength = header.BodyLength;

pub const PacketReader = reader.PacketReader;
pub const packetReader = reader.packetReader;
pub const PacketWriter = writer.PacketWriter;
pub const packetWriter = writer.packetWriter;

test {
    // Ensure all sub-module tests are run.
    @import("std").testing.refAllDecls(@This());
}
