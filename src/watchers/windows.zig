const std = @import("std");
const interfaces = @import("interfaces.zig");

pub const WindowsWatcher = struct {
    allocator: std.mem.Allocator,
    paths: std.ArrayList([]const u8),
    callback: ?*const interfaces.Callback,
    context: ?*anyopaque,
    running: bool,

    pub fn init(allocator: std.mem.Allocator) !WindowsWatcher {
        return WindowsWatcher{
            .allocator = allocator,
            .paths = std.ArrayList([]const u8).empty,
            .callback = null,
            .context = null,
            .running = false,
        };
    }

    pub fn deinit(self: *WindowsWatcher) void {
        self.stop();
        for (self.paths.items) |path| {
            self.allocator.free(path);
        }
        self.paths.deinit(self.allocator);
    }

    pub fn addFile(self: *WindowsWatcher, path: []const u8) !void {
        const dup_path = try self.allocator.dupe(u8, path);
        try self.paths.append(self.allocator, dup_path);
    }

    pub fn removeFile(self: *WindowsWatcher, path: []const u8) !void {
        for (self.paths.items, 0..) |item, i| {
            if (std.mem.eql(u8, item, path)) {
                self.allocator.free(self.paths.items[i]);
                _ = self.paths.orderedRemove(i);
                break;
            }
        }
    }

    pub fn setCallback(
        self: *WindowsWatcher,
        callback: interfaces.Callback,
        context: ?*anyopaque,
    ) void {
        self.callback = callback;
        self.context = context;
    }

    pub fn start(self: *WindowsWatcher, opts: interfaces.Opts) !void {
        if (self.paths.items.len == 0) return error.NoFilesToWatch;

        self.running = true;

        // Create a file handle and start monitoring for each path
        var handles = std.ArrayList(HandleInfo).empty;
        defer handles.deinit(self.allocator);

        for (self.paths.items) |path| {
            // Get directory path because ReadDirectoryChangesW needs to monitor directories
            var dir_path_end: usize = 0;
            for (path, 0..) |ch, i| {
                if (ch == '\\' or ch == '/') dir_path_end = i;
            }

            var dir_path: []const u8 = undefined;
            if (dir_path_end > 0) {
                dir_path = path[0..dir_path_end];
            } else {
                dir_path = ".";
            }

            // Convert path to wide characters
            const wide_dir_path_slice = try std.unicode.utf8ToUtf16LeAlloc(self.allocator, dir_path);
            defer self.allocator.free(wide_dir_path_slice);
            const wide_dir_path_with_null = try self.allocator.dupeZ(u16, wide_dir_path_slice);

            // Use Windows API from Zig standard library
            const dir_handle = std.os.windows.kernel32.CreateFileW(
                wide_dir_path_with_null.ptr,
                std.os.windows.FILE_LIST_DIRECTORY,
                std.os.windows.FILE_SHARE_READ | std.os.windows.FILE_SHARE_WRITE | std.os.windows.FILE_SHARE_DELETE,
                null,
                std.os.windows.OPEN_EXISTING,
                std.os.windows.FILE_FLAG_BACKUP_SEMANTICS,
                null,
            );

            if (dir_handle == std.os.windows.INVALID_HANDLE_VALUE) {
                return error.FileNotFound;
            }

            // Extract filename part for later matching - use reverse search
            var last_sep: ?usize = null;
            for (path, 0..) |ch, i| {
                if (ch == '\\' or ch == '/') last_sep = i;
            }

            const filename = if (last_sep) |sep| path[sep + 1 ..] else path;

            const handle_info = HandleInfo{
                .handle = dir_handle,
                .filename = try self.allocator.dupe(u8, filename),
                .path = try self.allocator.dupe(u8, path),
                .buffer = undefined,
            };
            try handles.append(self.allocator, handle_info);
            self.allocator.free(wide_dir_path_with_null);
        }

        defer {
            for (handles.items) |handle_info| {
                _ = std.os.windows.CloseHandle(handle_info.handle);
                self.allocator.free(handle_info.filename);
                self.allocator.free(handle_info.path);
            }
        }

        const notify_filter: std.os.windows.FileNotifyChangeFilter = .{
            .file_name = true,
            .dir_name = true,
            .attributes = true,
            .size = true,
            .last_write = true,
            .last_access = true,
            .creation = true,
            .security = true,
        };

        while (self.running) {
            for (handles.items) |*handle_info| {
                var bytes_returned: std.os.windows.DWORD = 0;

                const success = std.os.windows.kernel32.ReadDirectoryChangesW(
                    handle_info.handle,
                    &handle_info.buffer,
                    @sizeOf(@TypeOf(handle_info.buffer)),
                    0, // Don't monitor subdirectories
                    notify_filter,
                    &bytes_returned,
                    null,
                    null,
                );

                if (success != std.os.windows.FALSE) { // Success
                    if (bytes_returned > 0) {
                        var offset: usize = 0;

                        while (true) {
                            // Get FILE_NOTIFY_INFORMATION pointer from buffer offset
                            const record_ptr = @as([*]u8, @ptrCast(&handle_info.buffer[offset]));
                            const record = @as(*align(1) std.os.windows.FILE_NOTIFY_INFORMATION, @ptrCast(record_ptr));

                            // Get filename byte slice
                            const name_start = offset + @sizeOf(std.os.windows.FILE_NOTIFY_INFORMATION);
                            const name_slice = handle_info.buffer[name_start .. name_start + record.FileNameLength / 2 * 2]; // Length is in bytes, and UTF-16 chars are 2 bytes each

                            // Convert to UTF-16 slice
                            const utf16_name = @as([*]const u16, @ptrCast(@alignCast(name_slice.ptr)))[0 .. record.FileNameLength / 2];

                            // Convert filename from UTF-16 to UTF-8 string
                            var filename_utf8: [1024]u8 = undefined;
                            const filename_len = std.unicode.utf16LeToUtf8(&filename_utf8, utf16_name) catch {
                                // If conversion fails, skip this record
                                if (record.NextEntryOffset == 0) break;
                                offset += record.NextEntryOffset;
                                continue;
                            };

                            const event_filename = filename_utf8[0..filename_len];

                            // Check if this is the file we're monitoring
                            if (std.mem.eql(u8, event_filename, handle_info.filename)) {
                                if (self.callback) |callback| {
                                    callback(self.context, .modified);
                                }
                            }

                            if (record.NextEntryOffset == 0) break;
                            offset += record.NextEntryOffset;
                        }
                    }
                } else {
                    // Check for errors
                    const error_code = std.os.windows.GetLastError();
                    if (error_code != .IO_PENDING) {
                        // Log error but continue processing other files
                    }
                }

                // Sleep for a while to reduce CPU usage
                std.Thread.sleep(@as(u64, @intFromFloat(@as(f64, opts.latency) * @as(
                    f64,
                    @floatFromInt(std.time.ns_per_s),
                ))));
            }
        }
    }

    pub fn stop(self: *WindowsWatcher) void {
        self.running = false;
    }

    pub fn getNumberOfFilesBeingWatched(self: *WindowsWatcher) u32 {
        return @intCast(self.paths.items.len);
    }

    const HandleInfo = struct {
        handle: std.os.windows.HANDLE,
        filename: []const u8,
        path: []const u8,
        buffer: [4096]u8 align(8),
    };
};
