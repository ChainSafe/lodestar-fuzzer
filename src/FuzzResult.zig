const std = @import("std");
const Self = @This();

pub const Kind = enum {
    success,
    crash,
    hang,
};

branch: []const u8,
commit_sha: []const u8,
commit_timestamp: u64,
start_timestamp: u64,
target: []const u8,
edges_found: u64,
total_edges: u64,
unique_crashes: u64,
unique_hangs: u64,
total_execs: u64,
kind: Kind,
encoded_failure: []const u8,

pub fn lessThan(_: void, lhs: Self, rhs: Self) bool {
    if (lhs.commit_timestamp != rhs.commit_timestamp) {
        return lhs.commit_timestamp > rhs.commit_timestamp;
    }

    const lhs_failure = lhs.kind != .success;
    const rhs_failure = rhs.kind != .success;
    if (lhs_failure != rhs_failure) return lhs_failure;

    if (lhs.encoded_failure.len != rhs.encoded_failure.len) {
        return lhs.encoded_failure.len < rhs.encoded_failure.len;
    }
    if (lhs.start_timestamp != rhs.start_timestamp) {
        return lhs.start_timestamp > rhs.start_timestamp;
    }

    const target_order = std.mem.order(u8, lhs.target, rhs.target);
    if (target_order != .eq) return target_order == .lt;
    if (lhs.kind != rhs.kind) return @intFromEnum(lhs.kind) < @intFromEnum(rhs.kind);

    return std.mem.lessThan(u8, lhs.encoded_failure, rhs.encoded_failure);
}

pub fn sameRun(lhs: Self, rhs: Self) bool {
    return std.mem.eql(u8, lhs.branch, rhs.branch) and
        std.mem.eql(u8, lhs.commit_sha, rhs.commit_sha) and
        lhs.commit_timestamp == rhs.commit_timestamp and
        lhs.start_timestamp == rhs.start_timestamp and
        std.mem.eql(u8, lhs.target, rhs.target) and
        lhs.edges_found == rhs.edges_found and
        lhs.total_edges == rhs.total_edges and
        lhs.unique_crashes == rhs.unique_crashes and
        lhs.unique_hangs == rhs.unique_hangs and
        lhs.total_execs == rhs.total_execs;
}
