use super::*;

#[cfg(test)]
mod protection_tests {
    use super::{
        _exit, command_line_a, environment_block, linux_protection, load_native_child_image,
        native_acquire_srw_lock_exclusive, native_add_vectored_exception_handler,
        native_close_handle, native_connect_socket, native_create_process_w,
        native_create_waitable_timer_ex_w, native_decode_pointer, native_delete_critical_section,
        native_encode_pointer, native_enter_critical_section, native_extended_path,
        native_file_attributes, native_format_message_a, native_format_message_w,
        native_free_environment_strings_w, native_get_acp, native_get_computer_name_ex_w,
        native_get_console_cursor_info, native_get_console_mode, native_get_console_output_cp,
        native_get_console_screen_buffer_info, native_get_cp_info, native_get_current_directory_w,
        native_get_current_process, native_get_current_process_id, native_get_current_thread,
        native_get_current_thread_id, native_get_environment_strings_w,
        native_get_environment_variable_w, native_get_exit_code_process, native_get_file_type,
        native_get_full_path_name_w, native_get_last_error, native_get_module_file_name_w,
        native_get_module_handle_a, native_get_module_handle_ex_w, native_get_module_handle_w,
        native_get_oem_cp, native_get_proc_address, native_get_startup_info_w,
        native_get_string_type_w, native_get_system_info, native_get_user_profile_directory_w,
        native_global_memory_status_ex, native_heap_alloc, native_heap_free, native_heap_realloc,
        native_heap_size, native_init_once_execute_once, native_initialize_condition_variable,
        native_initialize_critical_section_and_spin_count, native_initialize_critical_section_ex,
        native_initialize_slist_head, native_initialize_srw_lock, native_interlocked_flush_slist,
        native_interlocked_pop_entry_slist, native_interlocked_push_entry_slist,
        native_ioctlsocket, native_is_processor_feature_present, native_is_valid_code_page,
        native_launch_spec, native_lc_map_string_w, native_leave_critical_section,
        native_listen_socket, native_multi_byte_to_wide_char,
        native_need_current_directory_for_exe_path_w, native_process_prng,
        native_query_depth_slist, native_query_performance_frequency, native_raise_exception,
        native_release_srw_lock_exclusive, native_release_srw_lock_shared,
        native_remove_vectored_exception_handler, native_resolve_code_page,
        native_rtl_add_function_table, native_rtl_delete_function_table, native_rtl_get_version,
        native_rtl_lookup_function_entry, native_rtl_nt_status_to_dos_error,
        native_set_console_active_screen_buffer, native_set_console_cursor_info,
        native_set_console_cursor_position, native_set_console_mode,
        native_set_console_screen_buffer_size, native_set_console_window_info,
        native_set_environment_variable_w, native_set_file_time, native_set_last_error,
        native_set_thread_stack_guarantee, native_set_unhandled_exception_filter,
        native_set_waitable_timer, native_shutdown_socket, native_sleep_condition_variable_srw,
        native_terminate_process, native_try_acquire_srw_lock_shared,
        native_wait_for_single_object, native_wait_on_address, native_wake_all_condition_variable,
        native_wake_by_address_all, native_wide_char_to_multi_byte, native_write_console_w,
        native_wsa_get_last_error, native_wsa_inet_addr, parse_windows_command_line, process_ctx,
        uppercase_ascii_utf16, waitpid, write_process_information, NativeLaunchSpec,
        NativeMemoryStatus, API_SET_MODULE, PROT_EXEC, PROT_READ, PROT_WRITE, THREAD_NATIVE_HANDLE,
    };
    use crate::winfs::WinFs;

    fn require_kernel32_api(name: &'static [u8]) -> u64 {
        let address = super::native_get_proc_address(super::API_SET_MODULE, name.as_ptr());
        let label = String::from_utf8_lossy(&name[..name.len().saturating_sub(1)]);
        assert_ne!(address, 0, "KERNEL32 API is not available: {label}");
        address
    }

    #[test]
    fn translates_standard_windows_page_protections() {
        assert_eq!(linux_protection(0x01), Some(0));
        assert_eq!(linux_protection(0x02), Some(PROT_READ));
        assert_eq!(linux_protection(0x04), Some(PROT_READ | PROT_WRITE));
        assert_eq!(linux_protection(0x10), Some(PROT_EXEC));
        assert_eq!(linux_protection(0x20), Some(PROT_READ | PROT_EXEC));
        assert_eq!(
            linux_protection(0x40),
            Some(PROT_READ | PROT_WRITE | PROT_EXEC)
        );
    }

    #[test]
    fn system_info_uses_windows_x64_field_offsets() {
        let mut info = [0u8; 48];
        native_get_system_info(info.as_mut_ptr());
        assert_eq!(u32::from_le_bytes(info[4..8].try_into().unwrap()), 4096);
        assert_eq!(u32::from_le_bytes(info[32..36].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(info[36..40].try_into().unwrap()), 8664);
        assert_eq!(u32::from_le_bytes(info[40..44].try_into().unwrap()), 65_536);
    }

    #[test]
    fn locale_name_query_supports_sizing_and_short_buffers() {
        assert_eq!(
            super::native_get_locale_info_ex(std::ptr::null(), 0x5c, std::ptr::null_mut(), 0),
            6
        );
        let mut short = [0u16; 2];
        assert_eq!(
            super::native_get_locale_info_ex(std::ptr::null(), 0x5c, short.as_mut_ptr(), 2),
            0
        );
        let mut value = [0u16; 6];
        assert_eq!(
            super::native_get_locale_info_ex(std::ptr::null(), 0x5c, value.as_mut_ptr(), 6),
            6
        );
        assert_eq!(String::from_utf16_lossy(&value[..5]), "en-US");
    }

    #[test]
    fn nt_read_file_tracks_offsets_and_reports_eof_and_invalid_handles() {
        let path = r"C:\nt_read_file_unit.txt";
        let context = super::fs_ctx().unwrap();
        let handle = {
            let mut fs = context.lock().unwrap();
            fs.fs.write_file(path, b"abcde".to_vec()).unwrap();
            let handle = fs.next;
            fs.next += 1;
            fs.handles.insert(
                handle,
                super::NativeFile {
                    path: path.into(),
                    offset: 0,
                    overlapped: false,
                    completion: None,
                },
            );
            handle
        };
        let mut io_status = [0u8; 16];
        let mut buffer = [0u8; 3];
        let read = |handle, offset: *const i64, io: &mut [u8; 16], output: &mut [u8; 3]| {
            super::native_nt_read_file(
                handle,
                0,
                0,
                0,
                io.as_mut_ptr(),
                output.as_mut_ptr(),
                3,
                offset,
                std::ptr::null(),
            )
        };
        assert_eq!(
            read(handle, std::ptr::null(), &mut io_status, &mut buffer),
            0
        );
        assert_eq!(&buffer, b"abc");
        assert_eq!(u64::from_le_bytes(io_status[8..16].try_into().unwrap()), 3);
        let explicit = 1i64;
        assert_eq!(read(handle, &explicit, &mut io_status, &mut buffer), 0);
        assert_eq!(&buffer, b"bcd");
        assert_eq!(
            read(handle, std::ptr::null(), &mut io_status, &mut buffer),
            0
        );
        assert_eq!(io_status[8], 1);
        assert_eq!(buffer[0], b'e');
        assert_eq!(
            read(handle, std::ptr::null(), &mut io_status, &mut buffer),
            0xC000_0011
        );
        assert_eq!(u64::from_le_bytes(io_status[8..16].try_into().unwrap()), 0);
        assert_eq!(
            read(u64::MAX - 10, std::ptr::null(), &mut io_status, &mut buffer),
            0xC000_0008
        );
        assert_eq!(
            super::native_nt_read_file(
                handle,
                1,
                0,
                0,
                io_status.as_mut_ptr(),
                buffer.as_mut_ptr(),
                3,
                std::ptr::null(),
                std::ptr::null()
            ),
            0xC000_00BB
        );
        let mut fs = context.lock().unwrap();
        fs.handles.remove(&handle);
        fs.fs.delete_file(path).unwrap();
    }

    #[test]
    fn nt_write_file_creates_and_extends_guest_files() {
        let path = r"C:\nt_write_file_unit.txt";
        let context = super::fs_ctx().unwrap();
        let handle = {
            let mut fs = context.lock().unwrap();
            fs.fs.write_file(path, b"abc".to_vec()).unwrap();
            let handle = fs.next;
            fs.next += 1;
            fs.handles.insert(
                handle,
                super::NativeFile {
                    path: path.into(),
                    offset: 0,
                    overlapped: false,
                    completion: None,
                },
            );
            handle
        };
        let mut io_status = [0u8; 16];
        let replacement = *b"XY";
        assert_eq!(
            super::native_nt_write_file(
                handle,
                0,
                0,
                0,
                io_status.as_mut_ptr(),
                replacement.as_ptr(),
                replacement.len() as u32,
                std::ptr::null(),
                std::ptr::null(),
            ),
            0
        );
        assert_eq!(u64::from_le_bytes(io_status[8..16].try_into().unwrap()), 2);
        assert_eq!(context.lock().unwrap().fs.read_file(path).unwrap(), b"XYc");

        let offset = 4i64;
        assert_eq!(
            super::native_nt_write_file(
                handle,
                0,
                0,
                0,
                io_status.as_mut_ptr(),
                replacement.as_ptr(),
                replacement.len() as u32,
                &offset,
                std::ptr::null(),
            ),
            0
        );
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"XYc\0XY"
        );

        let mut fs = context.lock().unwrap();
        fs.handles.remove(&handle);
        fs.fs.delete_file(path).unwrap();
    }

    #[test]
    fn nt_query_directory_file_returns_native_winfs_entries() {
        let directory = r"C:\nt_query_directory_unit";
        let context = super::fs_ctx().unwrap();
        {
            let mut fs = context.lock().unwrap();
            fs.fs.mkdir(directory).unwrap();
            fs.fs.mkdir(&format!(r"{directory}\nested")).unwrap();
            fs.fs
                .write_file(&format!(r"{directory}\alpha.txt"), b"a".to_vec())
                .unwrap();
            fs.fs
                .write_file(&format!(r"{directory}\nested\beta.txt"), b"b".to_vec())
                .unwrap();
            let handle = fs.next;
            fs.next += 1;
            fs.handles.insert(
                handle,
                super::NativeFile {
                    path: directory.to_string(),
                    offset: 0,
                    overlapped: false,
                    completion: None,
                },
            );
            drop(fs);

            let mut io_status = [0u8; 16];
            let mut entries = [0u8; 1024];
            assert_eq!(
                super::native_nt_query_directory_file(
                    handle,
                    0,
                    0,
                    0,
                    io_status.as_mut_ptr(),
                    entries.as_mut_ptr(),
                    entries.len() as u32,
                    1,
                    0,
                    std::ptr::null(),
                    1,
                ),
                0
            );
            assert_eq!(
                u64::from_le_bytes(io_status[8..16].try_into().unwrap()) as usize,
                88 + 76
            );
            let mut names = Vec::new();
            let mut offset = 0;
            loop {
                let next =
                    u32::from_le_bytes(entries[offset..offset + 4].try_into().unwrap()) as usize;
                let name_len =
                    u32::from_le_bytes(entries[offset + 60..offset + 64].try_into().unwrap())
                        as usize;
                let name = std::char::decode_utf16(
                    entries[offset + 64..offset + 64 + name_len]
                        .chunks_exact(2)
                        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]])),
                )
                .map(|character| character.unwrap())
                .collect::<String>();
                names.push(name);
                if next == 0 {
                    break;
                }
                offset += next;
            }
            names.sort();
            assert_eq!(names, ["alpha.txt", "nested"]);
            assert_eq!(
                super::native_nt_query_directory_file(
                    handle,
                    0,
                    0,
                    0,
                    io_status.as_mut_ptr(),
                    entries.as_mut_ptr(),
                    entries.len() as u32,
                    1,
                    0,
                    std::ptr::null(),
                    0,
                ),
                0x8000_0006
            );
            assert_eq!(
                super::native_nt_query_directory_file(
                    handle,
                    0,
                    0,
                    0,
                    io_status.as_mut_ptr(),
                    entries.as_mut_ptr(),
                    entries.len() as u32,
                    1,
                    0,
                    std::ptr::null(),
                    1,
                ),
                0
            );
            let mut fs = context.lock().unwrap();
            fs.handles.remove(&handle);
            fs.fs
                .delete_file(&format!(r"{directory}\alpha.txt"))
                .unwrap();
            fs.fs
                .delete_file(&format!(r"{directory}\nested\beta.txt"))
                .unwrap();
            fs.fs.rmdir(&format!(r"{directory}\nested")).unwrap();
            fs.fs.rmdir(directory).unwrap();
        }
    }

    #[test]
    fn get_file_information_by_handle_ex_reports_basic_metadata() {
        let path = r"C:\handle_ex_unit.txt";
        let context = super::fs_ctx().unwrap();
        let handle = {
            let mut fs = context.lock().unwrap();
            fs.fs.write_file(path, b"abcde".to_vec()).unwrap();
            let handle = fs.next;
            fs.next += 1;
            fs.handles.insert(
                handle,
                super::NativeFile {
                    path: path.into(),
                    offset: 0,
                    overlapped: false,
                    completion: None,
                },
            );
            handle
        };

        let mut standard = [0u8; 24];
        assert_eq!(
            super::native_get_file_information_by_handle_ex(
                handle,
                1,
                standard.as_mut_ptr(),
                standard.len() as u32,
            ),
            1
        );
        assert_eq!(i64::from_le_bytes(standard[8..16].try_into().unwrap()), 5);
        assert_eq!(u32::from_le_bytes(standard[16..20].try_into().unwrap()), 1);
        assert_eq!(standard[21], 0);
        let mut file_size = -1i64;
        assert_eq!(super::native_get_file_size_ex(handle, &mut file_size), 1);
        assert_eq!(file_size, 5);

        let mut attrs = [0u8; 8];
        assert_eq!(
            super::native_get_file_information_by_handle_ex(
                handle,
                9,
                attrs.as_mut_ptr(),
                attrs.len() as u32,
            ),
            1
        );
        assert_eq!(u32::from_le_bytes(attrs[..4].try_into().unwrap()), 0x80);

        assert_eq!(
            super::native_get_file_information_by_handle_ex(handle, 1, standard.as_mut_ptr(), 8,),
            0
        );
        assert_eq!(super::native_get_last_error(), 122);

        let mut basic = [0u8; 40];
        assert_eq!(
            super::native_get_file_information_by_handle_ex(
                handle,
                0,
                basic.as_mut_ptr(),
                basic.len() as u32,
            ),
            1
        );
        assert_eq!(u32::from_le_bytes(basic[32..36].try_into().unwrap()), 0x80);

        let mut file_id = [0u8; 24];
        assert_eq!(
            super::native_get_file_information_by_handle_ex(
                handle,
                18,
                file_id.as_mut_ptr(),
                file_id.len() as u32,
            ),
            1
        );
        assert_eq!(
            u64::from_le_bytes(file_id[..8].try_into().unwrap()),
            0x5743_4C49
        );
        assert_eq!(
            u64::from_le_bytes(file_id[8..16].try_into().unwrap()),
            context.lock().unwrap().fs.file_id(path).unwrap()
        );
        assert_eq!(
            super::native_get_file_information_by_handle_ex(handle, 18, file_id.as_mut_ptr(), 8,),
            0
        );
        assert_eq!(super::native_get_last_error(), 122);
        assert_eq!(
            super::native_get_file_information_by_handle_ex(
                handle,
                2,
                standard.as_mut_ptr(),
                standard.len() as u32,
            ),
            0
        );
        assert_eq!(super::native_get_last_error(), 87);
        assert_eq!(
            super::native_get_file_information_by_handle_ex(
                handle,
                1,
                std::ptr::null_mut(),
                standard.len() as u32,
            ),
            0
        );
        assert_eq!(super::native_get_last_error(), 998);
        assert_eq!(
            super::native_get_file_information_by_handle_ex(
                u64::MAX,
                1,
                standard.as_mut_ptr(),
                standard.len() as u32,
            ),
            0
        );
        assert_eq!(super::native_get_last_error(), 6);
    }

    #[test]
    fn get_file_information_by_handle_ex_reports_directory_metadata() {
        let path = r"C:\handle_ex_directory_unit";
        let context = super::fs_ctx().unwrap();
        let handle = {
            let mut fs = context.lock().unwrap();
            fs.fs.mkdir(path).unwrap();
            let handle = fs.next;
            fs.next += 1;
            fs.handles.insert(
                handle,
                super::NativeFile {
                    path: path.into(),
                    offset: 0,
                    overlapped: false,
                    completion: None,
                },
            );
            handle
        };

        let mut standard = [0u8; 24];
        assert_eq!(
            super::native_get_file_information_by_handle_ex(
                handle,
                1,
                standard.as_mut_ptr(),
                standard.len() as u32,
            ),
            1
        );
        assert_eq!(i64::from_le_bytes(standard[8..16].try_into().unwrap()), 0);
        assert_eq!(standard[21], 1);

        let mut attrs = [0u8; 8];
        assert_eq!(
            super::native_get_file_information_by_handle_ex(
                handle,
                9,
                attrs.as_mut_ptr(),
                attrs.len() as u32,
            ),
            1
        );
        assert_eq!(u32::from_le_bytes(attrs[..4].try_into().unwrap()), 0x10);

        let mut fs = context.lock().unwrap();
        fs.handles.remove(&handle);
        fs.fs.rmdir(path).unwrap();
    }

    #[test]
    fn create_file_supports_common_creation_dispositions() {
        let path = r"C:\create_disposition_unit.txt";
        let context = super::fs_ctx().unwrap();
        let wide_path = path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let create = |disposition| {
            super::native_create_file_w(wide_path.as_ptr(), 0, 0, 0, disposition, 0, 0)
        };

        let created = create(1); // CREATE_NEW
        assert_ne!(created, u64::MAX);
        assert!(context
            .lock()
            .unwrap()
            .fs
            .read_file(path)
            .unwrap()
            .is_empty());
        assert_eq!(super::native_close_handle(created), 1);
        assert_eq!(create(1), u64::MAX);
        assert_eq!(super::native_get_last_error(), 80);

        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"keep me".to_vec())
            .unwrap();
        let opened = create(4); // OPEN_ALWAYS preserves existing contents
        assert_ne!(opened, u64::MAX);
        assert_eq!(super::native_get_last_error(), 183);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"keep me"
        );
        let mut high = -1i32;
        assert_eq!(super::native_set_file_pointer(opened, -1, &mut high, 2), 6);
        assert_eq!(high, 0);
        assert_eq!(
            super::native_set_file_pointer(opened, 0, std::ptr::null_mut(), 0),
            0
        );
        assert_eq!(super::native_close_handle(opened), 1);

        let truncated = create(5); // TRUNCATE_EXISTING
        assert_ne!(truncated, u64::MAX);
        assert!(context
            .lock()
            .unwrap()
            .fs
            .read_file(path)
            .unwrap()
            .is_empty());
        assert_eq!(super::native_close_handle(truncated), 1);

        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_create_file_ansi_uses_windows_creation_dispositions() {
        let path = b"C:\\modern_create_file_ansi.txt\0";
        let context = super::fs_ctx().unwrap();
        let create =
            |disposition| super::native_create_file_a(path.as_ptr(), 0, 0, 0, disposition, 0, 0);

        let created = create(1); // CREATE_NEW
        assert_ne!(created, u64::MAX);
        assert_eq!(super::native_get_file_type(created), 1); // FILE_TYPE_DISK
        assert_eq!(super::native_close_handle(created), 1);
        assert_eq!(create(1), u64::MAX);
        assert_eq!(super::native_get_last_error(), 80); // ERROR_FILE_EXISTS

        context
            .lock()
            .unwrap()
            .fs
            .write_file(r"C:\modern_create_file_ansi.txt", b"preserve".to_vec())
            .unwrap();
        let opened = create(4); // OPEN_ALWAYS preserves existing data
        assert_ne!(opened, u64::MAX);
        assert_eq!(super::native_close_handle(opened), 1);
        assert_eq!(
            context
                .lock()
                .unwrap()
                .fs
                .read_file(r"C:\modern_create_file_ansi.txt")
                .unwrap(),
            b"preserve"
        );
        context
            .lock()
            .unwrap()
            .fs
            .delete_file(r"C:\modern_create_file_ansi.txt")
            .unwrap();
    }

    #[test]
    fn modern_find_first_file_ex_covers_all_reference_option_combinations() {
        let directory = r"C:\modern_find_ex_options";
        let pattern = format!(r"{directory}\*");
        let wide = |value: &str| value.encode_utf16().chain([0]).collect::<Vec<_>>();
        let pattern_wide = wide(&pattern);
        let context = super::fs_ctx().unwrap();
        {
            let mut fs = context.lock().unwrap();
            fs.fs.mkdir(directory).unwrap();
            fs.fs.mkdir(&format!(r"{directory}\nested")).unwrap();
            fs.fs
                .write_file(&format!(r"{directory}\Alpha.txt"), b"a".to_vec())
                .unwrap();
            fs.fs
                .write_file(&format!(r"{directory}\beta.bin"), b"b".to_vec())
                .unwrap();
        }

        for (info_level, search_op, flags) in [
            (0, 0, 0),
            (0, 0, 1),
            (0, 0, 2),
            (1, 0, 0),
            (0, 1, 0),
            (0, 1, 1),
            (0, 1, 2),
            (1, 1, 0),
        ] {
            let mut data = [0u8; 592];
            let find = super::native_find_first_file_ex_w(
                pattern_wide.as_ptr(),
                info_level,
                data.as_mut_ptr(),
                search_op,
                0,
                flags,
            );
            assert_ne!(find, u64::MAX, "{info_level}/{search_op}/{flags}");
            let mut names = Vec::new();
            loop {
                let encoded = unsafe {
                    std::slice::from_raw_parts(data.as_ptr().add(44).cast::<u16>(), 260)
                        .iter()
                        .copied()
                        .take_while(|unit| *unit != 0)
                        .collect::<Vec<_>>()
                };
                names.push(String::from_utf16(&encoded).unwrap());
                if super::native_find_next_file_w(find, data.as_mut_ptr()) == 0 {
                    break;
                }
            }
            names.sort();
            assert_eq!(
                names,
                ["Alpha.txt", "beta.bin", "nested"],
                "{info_level}/{search_op}/{flags}"
            );
            assert_eq!(super::native_find_close(find), 1);
        }

        let mut fs = context.lock().unwrap();
        fs.fs.remove(directory, true).unwrap();
        drop(fs);
    }

    #[test]
    fn modern_find_first_file_ex_reports_empty_missing_and_invalid_outputs() {
        let empty = r"C:\modern_find_ex_empty";
        let missing_pattern = r"C:\modern_find_ex_missing\*";
        let empty_pattern = format!(r"{empty}\*");
        let wide = |value: &str| value.encode_utf16().chain([0]).collect::<Vec<_>>();
        let empty_wide = wide(&empty_pattern);
        let missing_wide = wide(missing_pattern);
        let context = super::fs_ctx().unwrap();
        context.lock().unwrap().fs.mkdir(empty).unwrap();
        let mut data = [0u8; 592];

        assert_eq!(
            super::native_find_first_file_ex_w(empty_wide.as_ptr(), 0, data.as_mut_ptr(), 0, 0, 0,),
            u64::MAX
        );
        assert_eq!(super::native_get_last_error(), 2); // ERROR_FILE_NOT_FOUND
        assert_eq!(
            super::native_find_first_file_ex_w(
                missing_wide.as_ptr(),
                0,
                data.as_mut_ptr(),
                0,
                0,
                0,
            ),
            u64::MAX
        );
        assert_eq!(super::native_get_last_error(), 3); // ERROR_PATH_NOT_FOUND

        context
            .lock()
            .unwrap()
            .fs
            .write_file(&format!(r"{empty}\entry.txt"), b"x".to_vec())
            .unwrap();
        assert_eq!(
            super::native_find_first_file_ex_w(
                empty_wide.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                0,
                0,
            ),
            u64::MAX
        );
        assert_eq!(super::native_get_last_error(), 87); // ERROR_INVALID_PARAMETER

        let find =
            super::native_find_first_file_ex_w(empty_wide.as_ptr(), 0, data.as_mut_ptr(), 0, 0, 0);
        assert_ne!(find, u64::MAX);
        assert_eq!(
            super::native_find_next_file_w(u64::MAX, data.as_mut_ptr()),
            0
        );
        assert_eq!(super::native_find_close(find), 1);
        assert_eq!(super::native_find_close(find), 0);

        context.lock().unwrap().fs.remove(empty, true).unwrap();
    }

    #[test]
    fn modern_create_file_requires_backup_semantics_for_directory_handles() {
        let directory = r"C:\modern_create_file_directory_flags";
        let directory_wide = directory.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context.lock().unwrap().fs.mkdir(directory).unwrap();

        let with_backup = super::native_create_file_w(
            directory_wide.as_ptr(),
            0,
            0,
            0,
            3,
            0x0200_0000, // FILE_FLAG_BACKUP_SEMANTICS
            0,
        );
        assert_ne!(with_backup, u64::MAX);
        assert_eq!(super::native_close_handle(with_backup), 1);

        let without_backup = super::native_create_file_w(
            directory_wide.as_ptr(),
            0,
            0,
            0,
            3, // OPEN_EXISTING
            0,
            0,
        );
        assert_eq!(without_backup, u64::MAX);
        assert_eq!(super::native_get_last_error(), 5); // ERROR_ACCESS_DENIED
        context.lock().unwrap().fs.remove(directory, true).unwrap();
    }

    #[test]
    fn modern_create_file_posix_directory_attributes_create_a_directory() {
        let directory = r"C:\modern_posix_directory_creation";
        let context = super::fs_ctx().unwrap();
        context.lock().unwrap().fs.mkdir(directory).unwrap();
        let posix_directory = format!(r"{directory}\posix-created");
        let posix_wide = posix_directory
            .encode_utf16()
            .chain([0])
            .collect::<Vec<_>>();
        let dispositions = [(1, true), (4, false), (5, false), (2, true)];
        let flags = [0x0200_0000, 0x0200_0010, 0x0300_0010, 0x0100_0010];
        let mut mismatches = Vec::new();
        for (disposition, cleanup) in dispositions {
            for flag in flags {
                let handle = super::native_create_file_w(
                    posix_wide.as_ptr(),
                    0x4000_0000,
                    0x0000_0004,
                    0,
                    disposition,
                    flag,
                    0,
                );
                if handle == u64::MAX {
                    mismatches.push(format!(
                        "disposition={disposition} flags={flag:#x}: open failed"
                    ));
                    continue;
                }
                let is_directory = context.lock().unwrap().fs.is_dir(&posix_directory);
                let expect_directory = disposition == 1 && flag == 0x0300_0010;
                if is_directory != expect_directory {
                    mismatches.push(format!(
                        "disposition={disposition} flags={flag:#x}: directory={is_directory}, expected={expect_directory}"
                    ));
                }
                assert_eq!(super::native_close_handle(handle), 1);
                if cleanup {
                    let mut fs = context.lock().unwrap();
                    if fs.fs.exists(&posix_directory) {
                        fs.fs.remove(&posix_directory, true).unwrap();
                    }
                }
            }
        }
        assert!(mismatches.is_empty(), "POSIX create cases: {mismatches:?}");
        context.lock().unwrap().fs.remove(directory, true).unwrap();
    }

    #[test]
    fn move_file_ex_honors_replace_existing_and_rejects_bad_flags() {
        let context = super::fs_ctx().unwrap();
        let source = r"C:\move_file_ex_source.txt";
        let destination = r"C:\move_file_ex_destination.txt";
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs.write_file(source, b"new".to_vec()).unwrap();
            ctx.fs.write_file(destination, b"old".to_vec()).unwrap();
        }
        let source_wide = source
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let destination_wide = destination
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        assert_eq!(
            super::native_move_file_ex_w(source_wide.as_ptr(), destination_wide.as_ptr(), 0),
            0
        );
        assert_eq!(super::native_get_last_error(), 183);
        assert_eq!(
            super::native_move_file_ex_w(source_wide.as_ptr(), destination_wide.as_ptr(), 1),
            1
        );
        assert_eq!(
            context.lock().unwrap().fs.read_file(destination).unwrap(),
            b"new"
        );
        assert!(!context.lock().unwrap().fs.exists(source));
        assert_eq!(
            super::native_move_file_ex_w(source_wide.as_ptr(), destination_wide.as_ptr(), 4),
            0
        );
        assert_eq!(super::native_get_last_error(), 50);
        context.lock().unwrap().fs.delete_file(destination).unwrap();
    }

    #[test]
    fn win32_file_copy_move_enumerate_and_delete_roundtrip() {
        let directory = r"C:\winfs_compat_file_api_cases";
        let source = r"C:\winfs_compat_file_api_cases\source.txt";
        let copy = r"C:\winfs_compat_file_api_cases\copy.txt";
        let moved = r"C:\winfs_compat_file_api_cases\moved.txt";
        let wide = |value: &str| value.encode_utf16().chain([0]).collect::<Vec<_>>();
        let directory_wide = wide(directory);
        let source_wide = wide(source);
        let copy_wide = wide(copy);
        let moved_wide = wide(moved);
        let context = super::fs_ctx().unwrap();
        assert_eq!(
            super::native_create_directory_w(directory_wide.as_ptr(), 0),
            1
        );
        assert_eq!(
            super::native_create_directory_w(directory_wide.as_ptr(), 0),
            0
        );
        assert_eq!(super::native_get_last_error(), 183);

        let file = super::native_create_file_w(source_wide.as_ptr(), 0xC000_0000, 0, 0, 1, 0, 0);
        assert_ne!(file, u64::MAX);
        let payload = b"winfs-file-api";
        let mut written = 0;
        assert_eq!(
            super::native_write_file(
                file,
                payload.as_ptr(),
                payload.len() as u32,
                &mut written,
                0
            ),
            1
        );
        assert_eq!(written as usize, payload.len());
        assert_eq!(
            super::native_set_file_pointer(file, 0, std::ptr::null_mut(), 0),
            0
        );
        let mut read_buffer = [0u8; 32];
        let mut read = 0;
        assert_eq!(
            super::native_read_file(
                file,
                read_buffer.as_mut_ptr(),
                payload.len() as u32,
                &mut read,
                0
            ),
            1
        );
        assert_eq!(read as usize, payload.len());
        assert_eq!(&read_buffer[..read as usize], payload);
        let mut size = -1;
        assert_eq!(super::native_get_file_size_ex(file, &mut size), 1);
        assert_eq!(size, payload.len() as i64);
        assert_eq!(super::native_close_handle(file), 1);

        assert_eq!(
            super::native_copy_file_w(source_wide.as_ptr(), copy_wide.as_ptr(), 1),
            1
        );
        assert_eq!(
            super::native_copy_file_w(source_wide.as_ptr(), copy_wide.as_ptr(), 1),
            0
        );
        assert_eq!(context.lock().unwrap().fs.read_file(copy).unwrap(), payload);
        assert_eq!(
            super::native_move_file_w(copy_wide.as_ptr(), moved_wide.as_ptr()),
            1
        );
        assert!(!context.lock().unwrap().fs.exists(copy));

        let pattern = wide(r"C:\winfs_compat_file_api_cases\*");
        let mut find_data = [0u8; 592];
        let find = super::native_find_first_file_ex_w(
            pattern.as_ptr(),
            0,
            find_data.as_mut_ptr(),
            0,
            0,
            0,
        );
        assert_ne!(find, u64::MAX);
        let mut names = Vec::new();
        loop {
            let name = unsafe {
                std::slice::from_raw_parts(find_data.as_ptr().add(44).cast::<u16>(), 260)
                    .iter()
                    .copied()
                    .take_while(|unit| *unit != 0)
                    .collect::<Vec<_>>()
            };
            names.push(String::from_utf16(&name).unwrap());
            if super::native_find_next_file_w(find, find_data.as_mut_ptr()) == 0 {
                break;
            }
        }
        names.sort();
        assert_eq!(names, ["moved.txt", "source.txt"]);
        assert_eq!(super::native_find_close(find), 1);

        assert_eq!(super::native_delete_file_w(source_wide.as_ptr()), 1);
        assert_eq!(super::native_delete_file_w(moved_wide.as_ptr()), 1);
        assert_eq!(super::native_remove_directory_w(directory_wide.as_ptr()), 1);
        assert!(!context.lock().unwrap().fs.exists(directory));
    }

    #[test]
    fn win32_read_only_handle_rejects_write() {
        let path = r"C:\winfs_compat_readonly_access.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"read-only".to_vec())
            .unwrap();

        let handle = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 0, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let mut written = 0;
        let write = super::native_write_file(handle, b"x".as_ptr(), 1, &mut written, 0);
        assert_eq!(write, 0, "a GENERIC_READ handle must not allow writes");
        assert_eq!(super::native_get_last_error(), 5);
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn win32_share_mode_rejects_conflicting_open() {
        let path = r"C:\winfs_compat_sharing.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"shared".to_vec())
            .unwrap();

        let first = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 0, 0, 3, 0, 0);
        assert_ne!(first, u64::MAX);
        let conflicting = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 0, 0, 3, 0, 0);
        assert_eq!(conflicting, u64::MAX);
        assert_eq!(super::native_get_last_error(), 32);
        assert_eq!(super::native_close_handle(first), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn win32_find_first_file_filters_the_requested_name_pattern() {
        let directory = r"C:\winfs_compat_find_pattern";
        let directory_wide = directory.encode_utf16().chain([0]).collect::<Vec<_>>();
        let pattern = r"C:\winfs_compat_find_pattern\*.txt"
            .encode_utf16()
            .chain([0])
            .collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs.mkdir(directory).unwrap();
            ctx.fs
                .write_file(r"C:\winfs_compat_find_pattern\match.txt", b"x".to_vec())
                .unwrap();
            ctx.fs
                .write_file(r"C:\winfs_compat_find_pattern\ignore.bin", b"y".to_vec())
                .unwrap();
        }

        let mut data = [0u8; 592];
        let find =
            super::native_find_first_file_ex_w(pattern.as_ptr(), 0, data.as_mut_ptr(), 0, 0, 0);
        assert_ne!(find, u64::MAX);
        let name = unsafe {
            std::slice::from_raw_parts(data.as_ptr().add(44).cast::<u16>(), 260)
                .iter()
                .copied()
                .take_while(|unit| *unit != 0)
                .collect::<Vec<_>>()
        };
        let mut names = vec![String::from_utf16(&name).unwrap()];
        while super::native_find_next_file_w(find, data.as_mut_ptr()) != 0 {
            let name = unsafe {
                std::slice::from_raw_parts(data.as_ptr().add(44).cast::<u16>(), 260)
                    .iter()
                    .copied()
                    .take_while(|unit| *unit != 0)
                    .collect::<Vec<_>>()
            };
            names.push(String::from_utf16(&name).unwrap());
        }
        assert_eq!(super::native_find_close(find), 1);
        assert_eq!(names, ["match.txt"]);

        let mut ctx = context.lock().unwrap();
        ctx.fs
            .delete_file(r"C:\winfs_compat_find_pattern\match.txt")
            .unwrap();
        ctx.fs
            .delete_file(r"C:\winfs_compat_find_pattern\ignore.bin")
            .unwrap();
        drop(ctx);
        assert_eq!(super::native_remove_directory_w(directory_wide.as_ptr()), 1);
    }

    #[test]
    fn win32_set_file_time_accepts_a_guest_file_handle() {
        let path = r"C:\winfs_compat_set_time.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"time".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0, 0, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let timestamp = 132_537_600_000_000_000u64;
        assert_eq!(
            super::native_set_file_time(handle, &timestamp, &timestamp, &timestamp),
            1
        );
        let metadata = context.lock().unwrap().fs.file_metadata(path);
        assert_eq!(metadata.creation_time, timestamp);
        assert_eq!(metadata.access_time, timestamp);
        assert_eq!(metadata.write_time, timestamp);
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn win32_readonly_attribute_blocks_delete_file() {
        let path = r"C:\winfs_compat_readonly_delete.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"keep".to_vec())
            .unwrap();

        assert_eq!(super::native_set_file_attributes_w(wide.as_ptr(), 1), 1);
        assert_eq!(super::native_delete_file_w(wide.as_ptr()), 0);
        assert_eq!(super::native_get_last_error(), 5);
        assert!(context.lock().unwrap().fs.exists(path));
        assert_eq!(super::native_set_file_attributes_w(wide.as_ptr(), 0x80), 1);
        assert_eq!(super::native_delete_file_w(wide.as_ptr()), 1);
    }

    #[test]
    fn win32_get_final_path_supports_size_query_and_extended_path() {
        let path = r"C:\winfs_compat_final_path.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"path".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0, 0, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        let required =
            super::native_get_final_path_name_by_handle_w(handle, std::ptr::null_mut(), 0, 0);
        assert_eq!(
            required as usize,
            r"\\?\C:\winfs_compat_final_path.txt".encode_utf16().count() + 1
        );
        let mut short = vec![0xaaaa; required as usize - 1];
        assert_eq!(
            super::native_get_final_path_name_by_handle_w(
                handle,
                short.as_mut_ptr(),
                short.len() as u32,
                0,
            ),
            required
        );
        assert!(short.iter().all(|unit| *unit == 0xaaaa));
        let mut output = vec![0u16; required as usize];
        let written = super::native_get_final_path_name_by_handle_w(
            handle,
            output.as_mut_ptr(),
            output.len() as u32,
            0,
        );
        assert_eq!(written + 1, required);
        assert_eq!(
            String::from_utf16(&output[..written as usize]).unwrap(),
            r"\\?\C:\winfs_compat_final_path.txt"
        );
        let mut dos_path = vec![0u16; required as usize];
        let dos_written = super::native_get_final_path_name_by_handle_w(
            handle,
            dos_path.as_mut_ptr(),
            dos_path.len() as u32,
            1,
        );
        assert_eq!(dos_written, written);
        assert_eq!(
            &dos_path[..dos_written as usize],
            &output[..written as usize]
        );
        assert_eq!(
            super::native_get_final_path_name_by_handle_w(
                u64::MAX,
                output.as_mut_ptr(),
                output.len() as u32,
                0,
            ),
            0
        );

        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn nt_set_end_of_file_truncates_and_extends_guest_files() {
        let path = r"C:\winfs_compat_eof_resize.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"abcdef".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 0, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        let mut io_status = [0u8; 16];
        let mut eof = 3i64;
        let truncated = super::native_nt_set_information_file(
            handle,
            io_status.as_mut_ptr(),
            (&mut eof as *mut i64).cast(),
            8,
            20, // FileEndOfFileInformation
        );
        assert_eq!(truncated, 0);
        assert_eq!(context.lock().unwrap().fs.read_file(path).unwrap(), b"abc");

        eof = 6;
        let extended = super::native_nt_set_information_file(
            handle,
            io_status.as_mut_ptr(),
            (&mut eof as *mut i64).cast(),
            8,
            20,
        );
        assert_eq!(extended, 0);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"abc\0\0\0"
        );
        assert_eq!(super::native_close_handle(handle), 1);
    }

    #[test]
    fn nt_set_file_rename_information_renames_by_open_handle() {
        let source = r"C:\winfs_compat_rename_source.txt";
        let destination = r"C:\winfs_compat_rename_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(source, b"rename-me".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(source_wide.as_ptr(), 0xC000_0000, 0, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        // FILE_RENAME_INFORMATION: ReplaceIfExists, RootDirectory,
        // FileNameLength, then the UTF-16 destination path.
        let encoded = destination.encode_utf16().collect::<Vec<_>>();
        let mut information = vec![0u8; 20 + encoded.len() * 2];
        information[16..20].copy_from_slice(&((encoded.len() * 2) as u32).to_le_bytes());
        for (index, unit) in encoded.iter().enumerate() {
            information[20 + index * 2..22 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        let mut io_status = [0u8; 16];
        let status = super::native_nt_set_information_file(
            handle,
            io_status.as_mut_ptr(),
            information.as_ptr(),
            information.len() as u32,
            10, // FileRenameInformation
        );
        assert_eq!(status, 0);
        assert_eq!(
            context.lock().unwrap().fs.read_file(destination).unwrap(),
            b"rename-me"
        );
        assert!(!context.lock().unwrap().fs.exists(source));
        assert_eq!(super::native_close_handle(handle), 1);
    }

    #[test]
    fn nt_set_end_of_file_rejects_shrinking_an_active_mapped_view() {
        let path = r"C:\winfs_compat_eof_mapped.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"12345678".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 0, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let mapping = super::native_create_file_mapping_w(handle, 0, 0x04, 0, 8, std::ptr::null());
        assert_ne!(mapping, 0);
        let view = super::native_map_view_of_file(mapping, 0x2, 0, 0, 8);
        assert!(!view.is_null());

        let mut io_status = [0u8; 16];
        let mut eof = 4i64;
        let status = super::native_nt_set_information_file(
            handle,
            io_status.as_mut_ptr(),
            (&mut eof as *mut i64).cast(),
            8,
            20,
        );
        assert_eq!(super::native_unmap_view_of_file(view.cast()), 1);
        assert_eq!(super::native_close_handle(mapping), 1);
        assert_eq!(super::native_close_handle(handle), 1);
        assert_eq!(status, 0xC000_0022); // STATUS_ACCESS_DENIED while mapped
    }

    #[test]
    fn file_mapping_views_read_and_commit_guest_file_bytes() {
        let path = r"C:\file_mapping_unit.txt";
        let context = super::fs_ctx().unwrap();
        let handle = {
            let mut fs = context.lock().unwrap();
            fs.fs.write_file(path, b"abcdef".to_vec()).unwrap();
            let handle = fs.next;
            fs.next += 1;
            fs.handles.insert(
                handle,
                super::NativeFile {
                    path: path.into(),
                    offset: 0,
                    overlapped: false,
                    completion: None,
                },
            );
            handle
        };
        let mapping = super::native_create_file_mapping_w(handle, 0, 0x04, 0, 6, std::ptr::null());
        assert_ne!(mapping, 0);
        let view = super::native_map_view_of_file(mapping, 0x2, 0, 0, 0);
        assert!(!view.is_null());
        unsafe {
            assert_eq!(std::slice::from_raw_parts(view, 6), b"abcdef");
            view.add(1).write(b'Z');
        }
        assert_eq!(super::native_flush_view_of_file(view.cast(), 0), 1);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"aZcdef"
        );
        assert_eq!(super::native_unmap_view_of_file(view.cast()), 1);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"aZcdef"
        );
        assert_eq!(super::native_close_handle(mapping), 1);

        let extended = super::native_create_file_mapping_w(handle, 0, 0x04, 0, 9, std::ptr::null());
        assert_ne!(extended, 0);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"aZcdef\0\0\0"
        );
        let view = super::native_map_view_of_file(extended, 0x2, 0, 6, 3);
        assert!(!view.is_null());
        unsafe { std::ptr::copy_nonoverlapping(b"xyz".as_ptr(), view, 3) };
        assert_eq!(super::native_unmap_view_of_file(view.cast()), 1);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"aZcdefxyz"
        );
        assert_eq!(super::native_close_handle(extended), 1);

        let mut fs = context.lock().unwrap();
        fs.handles.remove(&handle);
        fs.fs.delete_file(path).unwrap();
    }

    #[test]
    fn overlapped_offset_combines_both_dwords() {
        let mut overlapped = [0u8; 32];
        overlapped[16..20].copy_from_slice(&0x89ab_cdefu32.to_le_bytes());
        overlapped[20..24].copy_from_slice(&0x1234u32.to_le_bytes());
        assert_eq!(
            super::native_overlapped_offset(overlapped.as_ptr() as u64),
            Some(0x1234_89ab_cdefusize)
        );
    }

    #[test]
    fn overlapped_result_reports_pending_completion_and_bad_handle() {
        let context = super::fs_ctx().unwrap();
        let handle = {
            let mut fs = context.lock().unwrap();
            let handle = fs.next;
            fs.next += 1;
            fs.handles.insert(
                handle,
                super::NativeFile {
                    path: r"C:\pending_result.txt".into(),
                    offset: 0,
                    overlapped: true,
                    completion: None,
                },
            );
            handle
        };
        let mut ov = [0u64; 4];
        let pointer = ov.as_mut_ptr() as u64;
        super::native_set_overlapped_status(pointer, super::STATUS_PENDING, 0);
        let mut bytes = 99;
        assert_eq!(
            super::native_get_overlapped_result(handle, pointer, &mut bytes, 0),
            0
        );
        assert_eq!(super::native_get_last_error(), 996);
        super::native_set_overlapped_status(pointer, 0, 7);
        assert_eq!(
            super::native_get_overlapped_result(handle, pointer, &mut bytes, 0),
            1
        );
        assert_eq!(bytes, 7);
        context.lock().unwrap().handles.remove(&handle);
        assert_eq!(
            super::native_get_overlapped_result(handle, pointer, &mut bytes, 0),
            0
        );
        assert_eq!(super::native_get_last_error(), 6);
    }

    #[test]
    fn overlapped_event_resets_before_io_and_signals_on_completion() {
        let handle = super::native_create_event_w(0, 1, 1, std::ptr::null());
        assert_ne!(handle, 0);
        assert_eq!(super::native_wait_for_single_object(handle, 0), 0);
        let mut ov = [0u64; 4];
        ov[3] = handle | 1;
        let event = super::native_prepare_overlapped_event(ov.as_ptr() as u64)
            .unwrap()
            .unwrap();
        assert_eq!(super::native_wait_for_single_object(handle, 0), 258);
        super::native_signal_event(&event);
        assert_eq!(super::native_wait_for_single_object(handle, 0), 0);
        assert_eq!(super::native_close_handle(handle), 1);
        assert_eq!(
            super::native_prepare_overlapped_event(ov.as_ptr() as u64).err(),
            Some(6)
        );
    }

    #[test]
    fn file_io_queue_reaches_its_fixed_capacity() {
        let process = super::process_ctx().unwrap();
        let file = super::NativeFile {
            path: r"C:\queue_unit.txt".into(),
            offset: 0,
            overlapped: true,
            completion: None,
        };
        let mut state = super::NativeFileIoQueueState {
            jobs: std::collections::VecDeque::new(),
            stop: false,
        };
        for _ in 0..super::MAX_QUEUED_FILE_IO {
            assert!(!super::native_file_io_queue_full(&state));
            state.jobs.push_back(super::NativeFileIoJob {
                process: std::sync::Arc::clone(&process),
                request: std::sync::Arc::new(super::NativePendingIo {
                    handle: 0,
                    overlapped: 0,
                    cancelled: super::AtomicBool::new(false),
                    issuer: std::thread::current().id(),
                }),
                file: file.clone(),
                overlapped: 0,
                event: None,
                offset: 0,
                operation: super::NativeFileIoOperation::Write { data: Vec::new() },
            });
        }
        assert!(super::native_file_io_queue_full(&state));
        let queue = super::NativeFileIoQueue {
            state: std::sync::Mutex::new(state),
            ready: std::sync::Condvar::new(),
        };
        let mut ov = [0u64; 4];
        ov[0] = 0x77;
        ov[3] = 0xdead; // invalid event must not be consulted when the queue is full
        assert_eq!(
            super::native_enqueue_file_io(
                &queue,
                &process,
                0,
                file,
                ov.as_mut_ptr() as u64,
                0,
                super::NativeFileIoOperation::Write { data: Vec::new() },
            ),
            Err(8)
        );
        assert_eq!(ov[0], 0x77);
        let mut state = queue.state.lock().unwrap();
        state.jobs.pop_front();
        assert!(!super::native_file_io_queue_full(&state));
    }

    #[test]
    fn queued_file_io_cancellation_signals_event_and_posts_failure() {
        let process = super::process_ctx().unwrap();
        let port = std::sync::Arc::new(super::NativeCompletionPort::new());
        let file = super::NativeFile {
            path: r"C:\cancel_unit.txt".into(),
            offset: 0,
            overlapped: true,
            completion: Some((std::sync::Arc::clone(&port), 0x1234)),
        };
        let handle = {
            let mut fs = process.fs.lock().unwrap();
            let handle = fs.next;
            fs.next += 1;
            fs.handles.insert(handle, file.clone());
            handle
        };
        let event_handle = super::native_create_event_w(0, 1, 0, std::ptr::null());
        assert_ne!(event_handle, 0);
        let mut ov = [0u64; 4];
        ov[3] = event_handle;
        let pointer = ov.as_mut_ptr() as u64;
        let event = super::native_prepare_overlapped_event(pointer).unwrap();
        super::native_set_overlapped_status(pointer, super::STATUS_PENDING, 0);
        let request = std::sync::Arc::new(super::NativePendingIo {
            handle,
            overlapped: pointer,
            cancelled: super::AtomicBool::new(false),
            issuer: std::thread::current().id(),
        });
        process
            .pending_requests
            .lock()
            .unwrap()
            .insert((handle, pointer), std::sync::Arc::clone(&request));
        let before = process
            .pending_file_io
            .fetch_add(1, super::Ordering::AcqRel);
        let queue = super::NativeFileIoQueue {
            state: std::sync::Mutex::new(super::NativeFileIoQueueState {
                jobs: std::collections::VecDeque::from([super::NativeFileIoJob {
                    process: std::sync::Arc::clone(&process),
                    request,
                    file,
                    overlapped: pointer,
                    event,
                    offset: 0,
                    operation: super::NativeFileIoOperation::Write { data: Vec::new() },
                }]),
                stop: false,
            }),
            ready: std::sync::Condvar::new(),
        };
        let another_issuer = std::thread::spawn(|| std::thread::current().id())
            .join()
            .unwrap();
        assert_eq!(
            super::native_cancel_file_io_requests(
                &process,
                &queue,
                handle,
                pointer,
                Some(another_issuer),
            ),
            Err(1168)
        );
        assert_eq!(
            super::native_overlapped_status(pointer),
            super::STATUS_PENDING
        );
        assert_eq!(
            super::native_cancel_file_io_requests(
                &process,
                &queue,
                handle,
                pointer,
                Some(std::thread::current().id()),
            ),
            Ok(())
        );
        assert_eq!(
            super::native_overlapped_status(pointer),
            super::STATUS_CANCELLED
        );
        let mut bytes = 9;
        assert_eq!(
            super::native_get_overlapped_result(handle, pointer, &mut bytes, 0),
            0
        );
        assert_eq!(super::native_get_last_error(), 995);
        assert_eq!(super::native_wait_for_single_object(event_handle, 0), 0);
        let packet = port.queue.lock().unwrap().pop_front().unwrap();
        assert_eq!(
            (packet.key, packet.overlapped, packet.bytes, packet.status),
            (0x1234, pointer, 0, super::STATUS_CANCELLED)
        );
        assert!(queue.state.lock().unwrap().jobs.is_empty());
        assert!(!process
            .pending_requests
            .lock()
            .unwrap()
            .contains_key(&(handle, pointer)));
        assert_eq!(
            process.pending_file_io.load(super::Ordering::Acquire),
            before
        );
        assert_eq!(
            super::native_cancel_file_io_requests(&process, &queue, handle, pointer, None),
            Err(1168)
        );
        assert_eq!(super::native_close_handle(event_handle), 1);
        process.fs.lock().unwrap().handles.remove(&handle);
    }

    #[test]
    fn last_error_is_private_to_each_native_thread() {
        native_set_last_error(87);
        let other = std::thread::spawn(|| {
            assert_eq!(native_get_last_error(), 0);
            native_set_last_error(6);
            native_get_last_error()
        });
        assert_eq!(other.join().unwrap(), 6);
        assert_eq!(native_get_last_error(), 87);
        native_set_last_error(0);
    }

    #[test]
    fn rejects_unsupported_windows_page_protections() {
        assert_eq!(linux_protection(0x08), None);
        assert_eq!(linux_protection(0x100), None);
    }

    #[test]
    fn tick_count_apis_report_monotonic_milliseconds() {
        let before = super::native_get_tick_count64();
        let tick32 = super::native_get_tick_count();
        let after = super::native_get_tick_count64();
        assert!(after >= before);
        assert!(tick32.wrapping_sub(before as u32) < 1000);
        assert!(super::baseline_trampoline("GetTickCount").is_some());
        assert!(super::baseline_trampoline("GetTickCount64").is_some());
    }

    #[test]
    fn user32_message_beep_is_a_successful_headless_noop() {
        assert!(super::supports_import("USER32.DLL", "MessageBeep"));
        assert_ne!(super::native_message_beep(0), 0);
    }

    #[test]
    fn crt_strncmp_compares_unsigned_bytes_within_the_requested_limit() {
        let left = b"nano\0";
        let same_prefix = b"name\0";
        let non_ascii = [0x80, 0];
        let ascii = [0x7f, 0];
        assert_eq!(
            super::native_crt_strncmp(left.as_ptr(), same_prefix.as_ptr(), 2),
            0
        );
        assert!(super::native_crt_strncmp(left.as_ptr(), same_prefix.as_ptr(), 3) > 0);
        assert!(super::native_crt_strncmp(non_ascii.as_ptr(), ascii.as_ptr(), 1) > 0);
        assert_eq!(
            super::native_crt_strncmp(std::ptr::null(), std::ptr::null(), 0),
            0
        );
    }

    #[test]
    fn crt_setlocale_exposes_the_supported_c_locale() {
        let c_locale = b"C\0";
        let locale = super::native_crt_setlocale(0, c_locale.as_ptr());
        assert!(!locale.is_null());
        assert_eq!(unsafe { std::slice::from_raw_parts(locale, 2) }, b"C\0");
        assert_eq!(super::native_crt_setlocale(0, std::ptr::null()), locale);
        assert!(super::native_crt_setlocale(6, std::ptr::null()).is_null());
        assert!(super::native_crt_setlocale(0, b"fr_FR\0".as_ptr()).is_null());
    }

    #[test]
    fn crt_strchr_finds_bytes_and_the_terminating_nul() {
        let text = b"nano\0";
        let found = super::native_crt_strchr(text.as_ptr(), b'n' as i32);
        assert_eq!(found, text.as_ptr() as *mut u8);
        assert_eq!(super::native_crt_strchr(text.as_ptr(), 0), unsafe {
            text.as_ptr().add(text.len() - 1) as *mut u8
        });
        assert!(super::native_crt_strchr(text.as_ptr(), b'z' as i32).is_null());
    }

    #[test]
    fn crt_strrchr_returns_the_last_matching_byte() {
        let text = b"nanometer\0";
        assert_eq!(
            super::native_crt_strrchr(text.as_ptr(), b'e' as i32),
            unsafe { text.as_ptr().add(7) as *mut u8 }
        );
        assert_eq!(super::native_crt_strrchr(text.as_ptr(), 0), unsafe {
            text.as_ptr().add(text.len() - 1) as *mut u8
        });
        assert!(super::native_crt_strrchr(text.as_ptr(), b'z' as i32).is_null());
    }

    #[test]
    fn crt_case_insensitive_string_comparisons_fold_ascii() {
        let upper = b"NaNo\0";
        let lower = b"nano\0";
        assert_eq!(super::native_crt_stricmp(upper.as_ptr(), lower.as_ptr()), 0);
        assert_eq!(
            super::native_crt_strnicmp(upper.as_ptr(), b"NAtch\0".as_ptr(), 2),
            0
        );
        assert!(super::native_crt_strnicmp(upper.as_ptr(), b"NAtch\0".as_ptr(), 3) < 0);
    }

    #[test]
    fn crt_atoi_parses_signed_decimal_prefixes() {
        assert_eq!(super::native_crt_atoi(b"  -42tail\0".as_ptr()), -42);
        assert_eq!(super::native_crt_atoi(b"+17\0".as_ptr()), 17);
        assert_eq!(super::native_crt_atoi(b"tail\0".as_ptr()), 0);
        assert_eq!(super::native_crt_atoi(std::ptr::null()), 0);
    }

    #[test]
    fn crt_case_conversion_matches_the_c_locale() {
        assert_eq!(super::native_crt_tolower(b'Q' as i32), b'q' as i32);
        assert_eq!(super::native_crt_tolower(b'?' as i32), b'?' as i32);
        assert_eq!(super::native_crt_toupper(b'q' as i32), b'Q' as i32);
        assert_eq!(super::native_crt_toupper(-1), -1);
    }

    #[test]
    fn crt_strncpy_zero_pads_short_sources() {
        let input = b"xy\0";
        let mut output = [0xff; 5];
        assert_eq!(
            super::native_crt_strncpy(output.as_mut_ptr(), input.as_ptr(), output.len()),
            output.as_mut_ptr()
        );
        assert_eq!(output, [b'x', b'y', 0, 0, 0]);
        let mut truncated = [0; 2];
        super::native_crt_strncpy(truncated.as_mut_ptr(), input.as_ptr(), 2);
        assert_eq!(truncated, [b'x', b'y']);
    }

    #[test]
    fn crt_calloc_zeroes_and_checks_size_overflow() {
        let allocation = super::native_crt_calloc(4, 2).cast::<u8>();
        assert!(!allocation.is_null());
        assert_eq!(
            unsafe { std::slice::from_raw_parts(allocation, 8) },
            &[0; 8]
        );
        super::native_crt_free(allocation.cast());
        assert!(super::native_crt_calloc(usize::MAX, 2).is_null());
    }

    #[test]
    fn crt_fwrite_handles_empty_and_overflowing_requests() {
        assert_eq!(
            super::native_crt_fwrite(std::ptr::null(), 0, 5, std::ptr::null_mut()),
            0
        );
        assert_eq!(
            super::native_crt_fwrite(std::ptr::null(), usize::MAX, 2, std::ptr::null_mut()),
            0
        );
    }

    #[test]
    fn crt_sprintf_formats_strings_integers_and_escaped_percent() {
        let name = b"nano\0";
        let format = b"%s:%04d %%\0";
        let mut output = [0u8; 32];
        let written = super::native_crt_sprintf(
            output.as_mut_ptr(),
            format.as_ptr(),
            name.as_ptr() as u64,
            (-7i32 as i64) as u64,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        assert_eq!(written, 11);
        assert_eq!(&output[..written as usize], b"nano:-007 %");
    }

    #[test]
    fn crt_strdup_returns_an_independent_nul_terminated_copy() {
        let input = b"nano\0";
        let duplicate = super::native_crt_strdup(input.as_ptr());
        assert!(!duplicate.is_null());
        assert_ne!(duplicate, input.as_ptr() as *mut u8);
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(duplicate.cast()) }.to_bytes(),
            b"nano"
        );
        super::native_crt_free(duplicate.cast());
        assert!(super::native_crt_strdup(std::ptr::null()).is_null());
    }

    #[test]
    fn crt_realloc_preserves_existing_bytes() {
        let allocation = super::native_crt_malloc(2).cast::<u8>();
        assert!(!allocation.is_null());
        unsafe { std::ptr::copy_nonoverlapping(b"ok".as_ptr(), allocation, 2) };
        let grown = super::native_crt_realloc(allocation.cast(), 8).cast::<u8>();
        assert!(!grown.is_null());
        assert_eq!(unsafe { std::slice::from_raw_parts(grown, 2) }, b"ok");
        super::native_crt_free(grown.cast());
        let fresh = super::native_crt_realloc(std::ptr::null_mut(), 8);
        assert!(!fresh.is_null());
        super::native_crt_free(fresh);
    }

    #[test]
    fn crt_wcstombs_converts_c_locale_and_reports_unrepresentable_text() {
        let input = [b'n' as u16, b'a' as u16, b'n' as u16, b'o' as u16, 0];
        let mut output = [0xff; 5];
        assert_eq!(
            super::native_crt_wcstombs(output.as_mut_ptr(), input.as_ptr(), output.len()),
            4
        );
        assert_eq!(&output, b"nano\0");
        assert_eq!(
            super::native_crt_wcstombs(std::ptr::null_mut(), input.as_ptr(), 0),
            4
        );
        assert_eq!(
            super::native_crt_wcstombs(output.as_mut_ptr(), input.as_ptr(), 2),
            2
        );
        let non_ascii = [0x00e9, 0];
        assert_eq!(
            super::native_crt_wcstombs(output.as_mut_ptr(), non_ascii.as_ptr(), output.len()),
            usize::MAX
        );
        assert_eq!(super::THREAD_CRT_ERRNO.with(std::cell::Cell::get), 42);
    }

    #[test]
    fn crt_mbstowcs_converts_c_locale_and_reports_unrepresentable_text() {
        let input = b"nano\0";
        let mut output = [u16::MAX; 5];
        assert_eq!(
            super::native_crt_mbstowcs(output.as_mut_ptr(), input.as_ptr(), output.len()),
            4
        );
        assert_eq!(
            &output,
            &[b'n' as u16, b'a' as u16, b'n' as u16, b'o' as u16, 0]
        );
        assert_eq!(
            super::native_crt_mbstowcs(std::ptr::null_mut(), input.as_ptr(), 0),
            4
        );
        assert_eq!(
            super::native_crt_mbstowcs(output.as_mut_ptr(), input.as_ptr(), 2),
            2
        );
        assert_eq!(
            super::native_crt_mbstowcs(output.as_mut_ptr(), b"\xe9\0".as_ptr(), output.len()),
            usize::MAX
        );
        assert_eq!(super::THREAD_CRT_ERRNO.with(std::cell::Cell::get), 42);
    }

    #[test]
    fn crt_stat64_reports_winfs_file_type_and_size() {
        let context = super::fs_ctx().unwrap();
        let path = r"C:\stat64_probe.txt";
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"probe".to_vec())
            .unwrap();
        let path = b"C:\\stat64_probe.txt\0";
        let mut status = [0u8; 56];
        assert_eq!(
            super::native_crt_stat64(path.as_ptr(), status.as_mut_ptr()),
            0
        );
        assert_eq!(u32::from_ne_bytes(status[..4].try_into().unwrap()), 2);
        assert_eq!(u16::from_ne_bytes(status[6..8].try_into().unwrap()), 0x8180);
        assert_eq!(i64::from_ne_bytes(status[24..32].try_into().unwrap()), 5);
        assert_eq!(
            super::native_crt_stat64(b"C:\\missing-stat64\0".as_ptr(), status.as_mut_ptr()),
            -1
        );
        assert_eq!(super::THREAD_CRT_ERRNO.with(std::cell::Cell::get), 2);
        context
            .lock()
            .unwrap()
            .fs
            .delete_file(r"C:\stat64_probe.txt")
            .unwrap();
    }

    #[test]
    fn crt_access_checks_winfs_paths_and_validates_modes() {
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(r"C:\access_probe.txt", b"x".to_vec())
            .unwrap();
        assert_eq!(
            super::native_crt_access(b"C:\\access_probe.txt\0".as_ptr(), 0),
            0
        );
        assert_eq!(
            super::native_crt_access(b"C:\\missing-access\0".as_ptr(), 0),
            -1
        );
        assert_eq!(
            super::native_crt_access(b"C:\\access_probe.txt\0".as_ptr(), 1),
            -1
        );
        assert_eq!(super::THREAD_CRT_ERRNO.with(std::cell::Cell::get), 22);
        context
            .lock()
            .unwrap()
            .fs
            .delete_file(r"C:\access_probe.txt")
            .unwrap();
    }

    #[test]
    fn crt_signal_records_handlers_per_process_and_rejects_invalid_numbers() {
        let process_id = super::process_ctx().unwrap().process_id;
        assert_eq!(super::native_crt_signal(2, 0x1234), 0);
        assert_eq!(super::native_crt_signal(2, 0x5678), 0x1234);
        assert_eq!(super::native_crt_signal(2, 0), 0x5678);
        assert_eq!(super::native_crt_signal(0, 0x1234), u64::MAX);
        assert!(super::supports_import("msvcrt.dll", "signal"));
        assert!(super::supports_import("MSVCRT.DLL", "signal"));
        super::NATIVE_CRT_SIGNAL_HANDLERS
            .lock()
            .unwrap()
            .remove(&(process_id, 2));
    }

    #[test]
    fn crt_errno_returns_thread_local_storage() {
        let errno = super::native_crt_errno();
        unsafe { errno.write(22) };
        let other_value = std::thread::spawn(|| {
            let other_errno = super::native_crt_errno();
            unsafe {
                other_errno.write(5);
                other_errno.read()
            }
        })
        .join()
        .unwrap();
        assert_eq!(other_value, 5);
        assert_eq!(unsafe { errno.read() }, 22);
    }

    #[test]
    fn crt_iob_func_returns_the_static_stream_table() {
        assert_eq!(
            super::native_crt_iob_func(),
            super::NATIVE_CRT_IOB.as_ptr().cast_mut().cast()
        );
    }

    #[test]
    fn crt_getenv_reads_guest_environment_case_insensitively() {
        let key: Vec<u16> = "WINRUN_TEST_CRT_GETENV"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let value: Vec<u16> = "guest-value"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        assert_eq!(
            super::native_set_environment_variable_w(key.as_ptr(), value.as_ptr()),
            1
        );
        let lookup = b"winrun_test_crt_getenv\0";
        let result = super::native_crt_getenv(lookup.as_ptr());
        assert!(!result.is_null());
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(result.cast()) }.to_bytes(),
            b"guest-value"
        );
        assert!(super::native_crt_getenv(b"WINRUN_MISSING_CRT_GETENV\0".as_ptr()).is_null());
        assert_eq!(
            super::native_set_environment_variable_w(key.as_ptr(), std::ptr::null()),
            1
        );
    }

    #[test]
    fn import_binding_checks_the_dll_as_well_as_the_function() {
        assert!(super::supports_import("MSVCRT.dll", "__lconv_init"));
        assert!(super::supports_import("MSVCRT.dll", "strncmp"));
        assert!(super::supports_import("MSVCRT.dll", "setlocale"));
        assert!(super::supports_import("MSVCRT.dll", "strchr"));
        assert!(super::supports_import("MSVCRT.dll", "strrchr"));
        assert!(super::supports_import("MSVCRT.dll", "_stricmp"));
        assert!(super::supports_import("MSVCRT.dll", "_strnicmp"));
        assert!(super::supports_import("MSVCRT.dll", "atoi"));
        assert!(super::supports_import("MSVCRT.dll", "tolower"));
        assert!(super::supports_import("MSVCRT.dll", "toupper"));
        assert!(super::supports_import("MSVCRT.dll", "strncpy"));
        assert!(super::supports_import("MSVCRT.dll", "mbstowcs"));
        assert!(super::supports_import("MSVCRT.dll", "calloc"));
        assert!(super::supports_import("MSVCRT.dll", "fwrite"));
        assert!(super::supports_import("MSVCRT.dll", "sprintf"));
        assert!(super::supports_import("MSVCRT.dll", "_errno"));
        assert!(super::supports_import("MSVCRT.dll", "getenv"));
        assert!(super::supports_import("MSVCRT.dll", "__iob_func"));
        assert!(super::supports_import("KERNEL32.dll", "ExitProcess"));
        assert!(super::supports_import("KERNEL32.dll", "GetShortPathNameW"));
        assert!(super::supports_import(
            "KERNEL32.dll",
            "GetConsoleCursorInfo"
        ));
        assert!(super::supports_import("KERNEL32.dll", "GetTickCount"));
        assert!(super::supports_import("KERNEL32.dll", "GetTickCount64"));
        assert!(super::supports_import("KERNEL32.dll", "RaiseException"));
        assert!(super::supports_import("NTDLL.dll", "RtlRaiseException"));
        assert!(super::supports_import("NTDLL.dll", "RtlAddFunctionTable"));
        assert!(super::supports_import(
            "NTDLL.dll",
            "RtlDeleteFunctionTable"
        ));
        assert!(super::supports_import(
            "NTDLL.dll",
            "RtlLookupFunctionEntry"
        ));
        assert!(super::supports_import(
            "api-ms-win-core-file-l1-1-0.dll",
            "CreateFileW"
        ));
        assert!(super::supports_import(
            "api-ms-win-core-synch-l1-2-0.dll",
            "WaitOnAddress"
        ));
        assert!(super::supports_import(
            "api-ms-win-crt-heap-l1-1-0.dll",
            "malloc"
        ));
        assert!(super::supports_import(
            "KERNEL32.dll",
            "NeedCurrentDirectoryForExePathW"
        ));
        assert!(super::supports_import("WINMM.dll", "timeGetTime"));
        assert!(!super::supports_import("USER32.dll", "ExitProcess"));
        assert!(!super::supports_import("KERNEL32.dll", "timeGetTime"));
        assert!(!super::supports_import("KERNEL32.dll", "NoSuchApi"));
        assert!(super::supports_import("WS2_32.dll", "#4"));
        assert!(super::supports_import("WS2_32.dll", "#10"));
        assert!(super::supports_import("WS2_32.dll", "#11"));
    }

    #[test]
    fn modern_file_api_imports_are_registered_for_compatibility_coverage() {
        // Keep the modern file-operation surface visible to Rust tests.
        // A missing binding is reported as a test failure so the API can
        // be added to the compatibility suite before its implementation.
        let apis = [
            "GetTempPathA",
            "GetTempPathW",
            "GetTempFileNameA",
            "GetTempFileNameW",
            "CopyFileA",
            "CopyFileW",
            "CopyFileExW",
            "CopyFile2",
            "CreateFileA",
            "CreateFileW",
            "CreateFile2",
            "DeleteFileA",
            "DeleteFileW",
            "MoveFileA",
            "MoveFileW",
            "FindFirstFileA",
            "FindFirstFileW",
            "FindNextFileA",
            "FindNextFileW",
            "FindFirstFileExA",
            "FindFirstFileExW",
            "LockFile",
            "UnlockFile",
            "GetFileType",
            "RemoveDirectoryA",
            "RemoveDirectoryW",
            "ReplaceFileA",
            "ReplaceFileW",
            "GetFileInformationByHandleEx",
            "OpenFileById",
            "SetFileValidData",
            "WriteFileGather",
            "GetFinalPathNameByHandleA",
            "GetFinalPathNameByHandleW",
            "SetFileInformationByHandle",
            "GetFileAttributesExW",
            "SetFileTime",
            "ReOpenFile",
            "CreateHardLinkW",
            "CreateSymbolicLinkW",
            "SetEndOfFile",
            "SetFilePointer",
            "SetFilePointerEx",
            "GetFileSizeEx",
            "GetFileInformationByHandle",
            "FlushFileBuffers",
            "GetOverlappedResult",
            "GetOverlappedResultEx",
            "CreateFileMappingA",
            "CreateFileMappingW",
            "MapViewOfFile",
            "UnmapViewOfFile",
            "GetQueuedCompletionStatus",
            "GetQueuedCompletionStatusEx",
            "PostQueuedCompletionStatus",
            "FindFirstStreamW",
            "SetFileCompletionNotificationModes",
            "CreateHardLinkA",
            "CreateSymbolicLinkA",
            "SetFileAttributesA",
            "SetFileAttributesW",
            "CreateDirectoryW",
            "MoveFileExW",
            "ReadFile",
            "WriteFile",
        ];
        let missing = apis
            .into_iter()
            .filter(|api| !super::supports_import("KERNEL32.dll", api))
            .collect::<Vec<_>>();
        assert!(missing.is_empty(), "unbound modern file APIs: {missing:?}");
    }

    macro_rules! modern_file_binding_cases {
        ($($test_name:ident: [$($api:literal),+ $(,)?]),+ $(,)?) => {
            $(
                #[test]
                fn $test_name() {
                    let missing = [$($api),+]
                        .into_iter()
                        .filter(|api| !super::supports_import("KERNEL32.dll", api))
                        .collect::<Vec<_>>();
                    assert!(missing.is_empty(), "unbound APIs: {missing:?}");
                }
            )+
        };
    }

    modern_file_binding_cases! {
        modern_temp_file_name_apis_are_bound: ["GetTempPathA", "GetTempPathW", "GetTempFileNameA", "GetTempFileNameW"],
        modern_copy_file_variants_are_bound: ["CopyFileA", "CopyFile2", "CopyFileExW"],
        modern_create_file2_is_bound: ["CreateFile2"],
        modern_ansi_delete_and_move_apis_are_bound: ["DeleteFileA", "MoveFileA"],
        modern_ansi_enumeration_apis_are_bound: ["FindFirstFileA", "FindNextFileA"],
        modern_ansi_extended_enumeration_is_bound: ["FindFirstFileExA"],
        modern_file_lock_apis_are_bound: ["LockFile", "UnlockFile"],
        modern_file_replace_apis_are_bound: ["ReplaceFileA", "ReplaceFileW"],
        modern_open_file_by_id_is_bound: ["OpenFileById"],
        modern_set_file_valid_data_is_bound: ["SetFileValidData"],
        modern_write_file_gather_is_bound: ["WriteFileGather"],
        modern_ansi_final_path_api_is_bound: ["GetFinalPathNameByHandleA"],
        modern_set_file_information_by_handle_is_bound: ["SetFileInformationByHandle"],
        modern_stream_enumeration_is_bound: ["FindFirstStreamW"],
        modern_reopen_file_is_bound: ["ReOpenFile"],
        modern_hard_link_apis_are_bound: ["CreateHardLinkA", "CreateHardLinkW"],
        modern_symbolic_link_apis_are_bound: ["CreateSymbolicLinkA", "CreateSymbolicLinkW"],
        modern_set_end_of_file_api_is_bound: ["SetEndOfFile"],
        modern_flush_file_buffers_api_is_bound: ["FlushFileBuffers"],
        modern_extended_overlapped_result_api_is_bound: ["GetOverlappedResultEx"],
        modern_ansi_file_attributes_api_is_bound: ["SetFileAttributesA"],
    }

    #[test]
    fn modern_reopen_file_preserves_guest_file_contents() {
        type ReOpenFile = unsafe extern "win64" fn(u64, u32, u32, u32) -> u64;
        let reopen: ReOpenFile =
            unsafe { std::mem::transmute(require_kernel32_api(b"ReOpenFile\0") as usize) };
        let path = r"C:\modern_reopen_file.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"reopen-data".to_vec())
            .unwrap();

        let original = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(original, u64::MAX);
        let reopened = unsafe { reopen(original, 0x8000_0000, 7, 0) };
        assert_ne!(reopened, u64::MAX);
        assert_eq!(super::native_get_file_type(reopened), 1);

        let mut bytes = [0u8; 11];
        let mut read = 0;
        assert_eq!(
            super::native_read_file(reopened, bytes.as_mut_ptr(), 11, &mut read, 0),
            1
        );
        assert_eq!(read, 11);
        assert_eq!(&bytes, b"reopen-data");
        assert_eq!(super::native_close_handle(reopened), 1);
        assert_eq!(super::native_close_handle(original), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_hard_link_shares_guest_file_identity_and_contents() {
        type CreateHardLinkW = unsafe extern "win64" fn(*const u16, *const u16, u64) -> i32;
        let create_link: CreateHardLinkW =
            unsafe { std::mem::transmute(require_kernel32_api(b"CreateHardLinkW\0") as usize) };
        let source = r"C:\modern_hard_link_source.txt";
        let link = r"C:\modern_hard_link_alias.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let link_wide = link.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(source, b"linked-content".to_vec())
            .unwrap();

        assert_eq!(
            unsafe { create_link(link_wide.as_ptr(), source_wide.as_ptr(), 0) },
            1
        );
        assert_eq!(
            context.lock().unwrap().fs.read_file(link).unwrap(),
            b"linked-content"
        );
        let source_handle =
            super::native_create_file_w(source_wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        let link_handle =
            super::native_create_file_w(link_wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(source_handle, u64::MAX);
        assert_ne!(link_handle, u64::MAX);
        let mut source_info = [0u8; 52];
        let mut link_info = [0u8; 52];
        assert_eq!(
            super::native_get_file_information_by_handle(source_handle, source_info.as_mut_ptr()),
            1
        );
        assert_eq!(
            super::native_get_file_information_by_handle(link_handle, link_info.as_mut_ptr()),
            1
        );
        assert_eq!(&source_info[44..52], &link_info[44..52]);
        assert_eq!(super::native_close_handle(link_handle), 1);
        assert_eq!(super::native_close_handle(source_handle), 1);
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(link).unwrap();
        ctx.fs.delete_file(source).unwrap();
    }

    #[test]
    fn modern_hard_link_does_not_replace_existing_destination() {
        type CreateHardLinkW = unsafe extern "win64" fn(*const u16, *const u16, u64) -> i32;
        let create_link: CreateHardLinkW =
            unsafe { std::mem::transmute(require_kernel32_api(b"CreateHardLinkW\0") as usize) };
        let source = r"C:\modern_hard_link_conflict_source.txt";
        let link = r"C:\modern_hard_link_conflict_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let link_wide = link.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs.write_file(source, b"source-data".to_vec()).unwrap();
            ctx.fs
                .write_file(link, b"destination-data".to_vec())
                .unwrap();
        }

        let result = unsafe { create_link(link_wide.as_ptr(), source_wide.as_ptr(), 0) };
        let source_bytes = context.lock().unwrap().fs.read_file(source).unwrap();
        let link_bytes = context.lock().unwrap().fs.read_file(link).unwrap();
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(link).unwrap();
        ctx.fs.delete_file(source).unwrap();
        assert_eq!(result, 0);
        assert_eq!(source_bytes, b"source-data");
        assert_eq!(link_bytes, b"destination-data");
    }

    #[test]
    fn modern_replace_file_moves_old_contents_to_backup() {
        type ReplaceFileW =
            unsafe extern "win64" fn(*const u16, *const u16, *const u16, u32, u64, u64) -> i32;
        let replace: ReplaceFileW =
            unsafe { std::mem::transmute(require_kernel32_api(b"ReplaceFileW\0") as usize) };
        let destination = r"C:\modern_replace_destination.txt";
        let replacement = r"C:\modern_replace_new.txt";
        let backup = r"C:\modern_replace_backup.txt";
        let destination_wide = destination.encode_utf16().chain([0]).collect::<Vec<_>>();
        let replacement_wide = replacement.encode_utf16().chain([0]).collect::<Vec<_>>();
        let backup_wide = backup.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs
                .write_file(destination, b"old-value".to_vec())
                .unwrap();
            ctx.fs
                .write_file(replacement, b"new-value".to_vec())
                .unwrap();
        }

        assert_eq!(
            unsafe {
                replace(
                    destination_wide.as_ptr(),
                    replacement_wide.as_ptr(),
                    backup_wide.as_ptr(),
                    0,
                    0,
                    0,
                )
            },
            1
        );
        let ctx = context.lock().unwrap();
        assert_eq!(ctx.fs.read_file(destination).unwrap(), b"new-value");
        assert_eq!(ctx.fs.read_file(backup).unwrap(), b"old-value");
        assert!(!ctx.fs.exists(replacement));
        drop(ctx);
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(backup).unwrap();
        ctx.fs.delete_file(destination).unwrap();
    }

    #[test]
    fn modern_lock_file_locks_and_unlocks_a_byte_range() {
        type FileRangeOperation = unsafe extern "win64" fn(u64, u32, u32, u32, u32) -> i32;
        let lock: FileRangeOperation =
            unsafe { std::mem::transmute(require_kernel32_api(b"LockFile\0") as usize) };
        let unlock: FileRangeOperation =
            unsafe { std::mem::transmute(require_kernel32_api(b"UnlockFile\0") as usize) };
        let path = r"C:\modern_lock_file.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"lock".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        assert_eq!(unsafe { lock(handle, 1, 0, 1, 0) }, 1);
        assert_eq!(unsafe { unlock(handle, 1, 0, 1, 0) }, 1);
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_lock_file_rejects_overlapping_lock_until_unlocked() {
        type FileRangeOperation = unsafe extern "win64" fn(u64, u32, u32, u32, u32) -> i32;
        let lock: FileRangeOperation =
            unsafe { std::mem::transmute(require_kernel32_api(b"LockFile\0") as usize) };
        let unlock: FileRangeOperation =
            unsafe { std::mem::transmute(require_kernel32_api(b"UnlockFile\0") as usize) };
        let path = r"C:\modern_lock_conflict.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"locked-range".to_vec())
            .unwrap();
        let first = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0);
        let second = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0);
        assert_ne!(first, u64::MAX);
        assert_ne!(second, u64::MAX);

        assert_eq!(unsafe { lock(first, 2, 0, 4, 0) }, 1);
        assert_eq!(unsafe { lock(second, 4, 0, 2, 0) }, 0);
        let conflict_error = super::native_get_last_error();
        assert_eq!(unsafe { unlock(first, 2, 0, 4, 0) }, 1);
        let after_unlock = unsafe { lock(second, 2, 0, 4, 0) };
        assert_eq!(unsafe { unlock(second, 2, 0, 4, 0) }, 1);
        assert_eq!(super::native_close_handle(second), 1);
        assert_eq!(super::native_close_handle(first), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();

        assert_eq!(conflict_error, 33); // ERROR_LOCK_VIOLATION
        assert_eq!(after_unlock, 1);
    }

    #[test]
    fn modern_ansi_move_file_moves_guest_data_without_changing_contents() {
        type MoveFileA = unsafe extern "win64" fn(*const u8, *const u8) -> i32;
        let move_file: MoveFileA =
            unsafe { std::mem::transmute(require_kernel32_api(b"MoveFileA\0") as usize) };
        let source = b"C:\\modern_move_ansi_source.txt\0";
        let destination = b"C:\\modern_move_ansi_destination.txt\0";
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file("C:\\modern_move_ansi_source.txt", b"move-data".to_vec())
            .unwrap();

        assert_eq!(
            unsafe { move_file(source.as_ptr(), destination.as_ptr()) },
            1
        );
        let ctx = context.lock().unwrap();
        assert!(!ctx.fs.exists("C:\\modern_move_ansi_source.txt"));
        assert_eq!(
            ctx.fs
                .read_file("C:\\modern_move_ansi_destination.txt")
                .unwrap(),
            b"move-data"
        );
        drop(ctx);
        context
            .lock()
            .unwrap()
            .fs
            .delete_file("C:\\modern_move_ansi_destination.txt")
            .unwrap();
    }

    #[test]
    fn modern_ansi_delete_file_removes_guest_file() {
        type DeleteFileA = unsafe extern "win64" fn(*const u8) -> i32;
        let delete_file: DeleteFileA =
            unsafe { std::mem::transmute(require_kernel32_api(b"DeleteFileA\0") as usize) };
        let path = b"C:\\modern_delete_ansi.txt\0";
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file("C:\\modern_delete_ansi.txt", b"delete-me".to_vec())
            .unwrap();

        assert_eq!(unsafe { delete_file(path.as_ptr()) }, 1);
        assert!(!context
            .lock()
            .unwrap()
            .fs
            .exists("C:\\modern_delete_ansi.txt"));
    }

    #[test]
    fn modern_wide_move_file_moves_guest_data_without_changing_contents() {
        type MoveFileW = unsafe extern "win64" fn(*const u16, *const u16) -> i32;
        let move_file: MoveFileW =
            unsafe { std::mem::transmute(require_kernel32_api(b"MoveFileW\0") as usize) };
        let source = r"C:\modern_move_wide_source.txt";
        let destination = r"C:\modern_move_wide_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let destination_wide = destination.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(source, b"wide-move-data".to_vec())
            .unwrap();

        assert_eq!(
            unsafe { move_file(source_wide.as_ptr(), destination_wide.as_ptr()) },
            1
        );
        let ctx = context.lock().unwrap();
        assert!(!ctx.fs.exists(source));
        assert_eq!(ctx.fs.read_file(destination).unwrap(), b"wide-move-data");
        drop(ctx);
        context.lock().unwrap().fs.delete_file(destination).unwrap();
    }

    #[test]
    fn modern_wide_move_file_preserves_existing_destination() {
        type MoveFileW = unsafe extern "win64" fn(*const u16, *const u16) -> i32;
        let move_file: MoveFileW =
            unsafe { std::mem::transmute(require_kernel32_api(b"MoveFileW\0") as usize) };
        let source = r"C:\modern_move_wide_conflict_source.txt";
        let destination = r"C:\modern_move_wide_conflict_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let destination_wide = destination.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs.write_file(source, b"source-data".to_vec()).unwrap();
            ctx.fs
                .write_file(destination, b"destination-data".to_vec())
                .unwrap();
        }

        assert_eq!(
            unsafe { move_file(source_wide.as_ptr(), destination_wide.as_ptr()) },
            0
        );
        let error = super::native_get_last_error();
        let ctx = context.lock().unwrap();
        assert!(ctx.fs.exists(source));
        assert_eq!(ctx.fs.read_file(source).unwrap(), b"source-data");
        assert_eq!(ctx.fs.read_file(destination).unwrap(), b"destination-data");
        drop(ctx);
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(source).unwrap();
        ctx.fs.delete_file(destination).unwrap();
        assert_eq!(error, 183); // ERROR_ALREADY_EXISTS
    }

    #[test]
    fn modern_wide_delete_file_removes_guest_file() {
        type DeleteFileW = unsafe extern "win64" fn(*const u16) -> i32;
        let delete_file: DeleteFileW =
            unsafe { std::mem::transmute(require_kernel32_api(b"DeleteFileW\0") as usize) };
        let path = r"C:\modern_delete_wide.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"wide-delete-me".to_vec())
            .unwrap();

        assert_eq!(unsafe { delete_file(wide.as_ptr()) }, 1);
        assert!(!context.lock().unwrap().fs.exists(path));
    }

    #[test]
    fn modern_wide_delete_file_reports_missing_path() {
        type DeleteFileW = unsafe extern "win64" fn(*const u16) -> i32;
        let delete_file: DeleteFileW =
            unsafe { std::mem::transmute(require_kernel32_api(b"DeleteFileW\0") as usize) };
        let path = r"C:\modern_delete_wide_missing.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();

        assert_eq!(unsafe { delete_file(wide.as_ptr()) }, 0);
        assert_eq!(super::native_get_last_error(), 2); // ERROR_FILE_NOT_FOUND
    }

    #[test]
    fn modern_copy_file_a_copies_data_and_honors_fail_if_exists() {
        type CopyFileA = unsafe extern "win64" fn(*const u8, *const u8, i32) -> i32;
        let copy_file: CopyFileA =
            unsafe { std::mem::transmute(require_kernel32_api(b"CopyFileA\0") as usize) };
        let source = b"C:\\modern_copy_ansi_source.txt\0";
        let destination = b"C:\\modern_copy_ansi_destination.txt\0";
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file("C:\\modern_copy_ansi_source.txt", b"copy-data".to_vec())
            .unwrap();

        assert_eq!(
            unsafe { copy_file(source.as_ptr(), destination.as_ptr(), 1) },
            1
        );
        assert_eq!(
            context
                .lock()
                .unwrap()
                .fs
                .read_file("C:\\modern_copy_ansi_destination.txt")
                .unwrap(),
            b"copy-data"
        );
        assert_eq!(
            unsafe { copy_file(source.as_ptr(), destination.as_ptr(), 1) },
            0
        );
        assert_eq!(super::native_get_last_error(), 80);
        let mut ctx = context.lock().unwrap();
        ctx.fs
            .delete_file("C:\\modern_copy_ansi_destination.txt")
            .unwrap();
        ctx.fs
            .delete_file("C:\\modern_copy_ansi_source.txt")
            .unwrap();
    }

    #[test]
    fn modern_ansi_final_path_returns_the_open_guest_path() {
        type GetFinalPathNameByHandleA = unsafe extern "win64" fn(u64, *mut u8, u32, u32) -> u32;
        let get_path: GetFinalPathNameByHandleA = unsafe {
            std::mem::transmute(require_kernel32_api(b"GetFinalPathNameByHandleA\0") as usize)
        };
        let path = r"C:\modern_final_path_ansi.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"path-data".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        let mut output = [0u8; 128];
        let written = unsafe { get_path(handle, output.as_mut_ptr(), output.len() as u32, 0) };
        assert_eq!(
            &output[..written as usize],
            b"\\\\?\\C:\\modern_final_path_ansi.txt"
        );
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_temp_file_name_creates_a_unique_guest_file() {
        type GetTempPathW = unsafe extern "win64" fn(u32, *mut u16) -> u32;
        type GetTempFileNameW =
            unsafe extern "win64" fn(*const u16, *const u16, u32, *mut u16) -> u32;
        let get_temp_path: GetTempPathW =
            unsafe { std::mem::transmute(require_kernel32_api(b"GetTempPathW\0") as usize) };
        let get_temp_file: GetTempFileNameW =
            unsafe { std::mem::transmute(require_kernel32_api(b"GetTempFileNameW\0") as usize) };
        let mut directory = [0u16; 512];
        let length =
            unsafe { get_temp_path(directory.len() as u32, directory.as_mut_ptr()) } as usize;
        assert!(length > 0 && length < directory.len());
        assert_eq!(directory[length], 0);
        let prefix = [b'w' as u16, b'f' as u16, b's' as u16, 0];
        let mut filename = [0u16; 1024];
        assert_ne!(
            unsafe {
                get_temp_file(
                    directory.as_ptr(),
                    prefix.as_ptr(),
                    0,
                    filename.as_mut_ptr(),
                )
            },
            0
        );
        let path =
            String::from_utf16(&filename[..filename.iter().position(|unit| *unit == 0).unwrap()])
                .unwrap();
        let context = super::fs_ctx().unwrap();
        assert!(context.lock().unwrap().fs.exists(&path));
        context.lock().unwrap().fs.delete_file(&path).unwrap();
    }

    #[test]
    fn modern_create_file2_opens_existing_guest_file() {
        type CreateFile2 =
            unsafe extern "win64" fn(*const u16, u32, u32, u32, *const std::ffi::c_void) -> u64;
        let create_file2: CreateFile2 =
            unsafe { std::mem::transmute(require_kernel32_api(b"CreateFile2\0") as usize) };
        let path = r"C:\modern_create_file2.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"create-file2-data".to_vec())
            .unwrap();

        let handle = unsafe { create_file2(wide.as_ptr(), 0x8000_0000, 7, 3, std::ptr::null()) };
        assert_ne!(handle, u64::MAX);
        let mut bytes = [0u8; 17];
        let mut read = 0;
        assert_eq!(
            super::native_read_file(handle, bytes.as_mut_ptr(), 17, &mut read, 0),
            1
        );
        assert_eq!(read, 17);
        assert_eq!(&bytes, b"create-file2-data");
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_copy_file2_copies_contents_and_preserves_source() {
        type CopyFile2 =
            unsafe extern "win64" fn(*const u16, *const u16, *const std::ffi::c_void) -> i32;
        let copy_file2: CopyFile2 =
            unsafe { std::mem::transmute(require_kernel32_api(b"CopyFile2\0") as usize) };
        let source = r"C:\modern_copy_file2_source.txt";
        let destination = r"C:\modern_copy_file2_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let destination_wide = destination.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(source, b"copy-file2-source".to_vec())
            .unwrap();

        assert_eq!(
            unsafe {
                copy_file2(
                    source_wide.as_ptr(),
                    destination_wide.as_ptr(),
                    std::ptr::null(),
                )
            },
            0 // HRESULT S_OK
        );
        assert_eq!(
            context.lock().unwrap().fs.read_file(destination).unwrap(),
            b"copy-file2-source"
        );
        assert_eq!(
            context.lock().unwrap().fs.read_file(source).unwrap(),
            b"copy-file2-source"
        );
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(destination).unwrap();
        ctx.fs.delete_file(source).unwrap();
    }

    #[test]
    fn modern_copy_file_ex_honors_fail_if_exists_flag() {
        type CopyFileExW =
            unsafe extern "win64" fn(*const u16, *const u16, u64, u64, *mut i32, u32) -> i32;
        let copy_file_ex: CopyFileExW =
            unsafe { std::mem::transmute(require_kernel32_api(b"CopyFileExW\0") as usize) };
        let source = r"C:\modern_copy_file_ex_source.txt";
        let destination = r"C:\modern_copy_file_ex_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let destination_wide = destination.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs
                .write_file(source, b"copy-ex-source".to_vec())
                .unwrap();
            ctx.fs
                .write_file(destination, b"keep-existing".to_vec())
                .unwrap();
        }

        assert_eq!(
            unsafe {
                copy_file_ex(
                    source_wide.as_ptr(),
                    destination_wide.as_ptr(),
                    0,
                    0,
                    std::ptr::null_mut(),
                    1,
                )
            },
            0
        );
        assert_eq!(super::native_get_last_error(), 80);
        assert_eq!(
            context.lock().unwrap().fs.read_file(destination).unwrap(),
            b"keep-existing"
        );
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(destination).unwrap();
        ctx.fs.delete_file(source).unwrap();
    }

    #[test]
    fn modern_find_first_stream_reports_the_default_data_stream() {
        type FindFirstStreamW =
            unsafe extern "win64" fn(*const u16, i32, *mut std::ffi::c_void, u32) -> u64;
        let find_first_stream: FindFirstStreamW =
            unsafe { std::mem::transmute(require_kernel32_api(b"FindFirstStreamW\0") as usize) };
        let path = r"C:\modern_stream_enumeration.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"stream-content".to_vec())
            .unwrap();

        let mut stream_data = [0u8; 600];
        let find =
            unsafe { find_first_stream(wide.as_ptr(), 0, stream_data.as_mut_ptr().cast(), 0) };
        assert_ne!(find, u64::MAX);
        assert_eq!(i64::from_le_bytes(stream_data[..8].try_into().unwrap()), 14);
        let stream_name = unsafe {
            std::slice::from_raw_parts(stream_data.as_ptr().add(8).cast::<u16>(), 296)
                .iter()
                .copied()
                .take_while(|unit| *unit != 0)
                .collect::<Vec<_>>()
        };
        assert_eq!(String::from_utf16(&stream_name).unwrap(), r"::$DATA");
        assert_eq!(super::native_find_close(find), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_set_file_information_by_handle_deletes_on_last_close() {
        type SetFileInformationByHandle =
            unsafe extern "win64" fn(u64, i32, *const std::ffi::c_void, u32) -> i32;
        let set_information: SetFileInformationByHandle = unsafe {
            std::mem::transmute(require_kernel32_api(b"SetFileInformationByHandle\0") as usize)
        };
        let path = r"C:\modern_disposition_by_handle.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"delete-on-close".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0x0001_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        let disposition = [1u8]; // FILE_DISPOSITION_INFO.DeleteFile
        assert_eq!(
            unsafe {
                set_information(
                    handle,
                    4,
                    disposition.as_ptr().cast(),
                    disposition.len() as u32,
                )
            },
            1
        );
        assert!(context.lock().unwrap().fs.exists(path));
        assert_eq!(super::native_close_handle(handle), 1);
        assert!(!context.lock().unwrap().fs.exists(path));
    }

    #[test]
    fn modern_set_file_information_by_handle_rejects_unknown_class() {
        type SetFileInformationByHandle =
            unsafe extern "win64" fn(u64, i32, *const std::ffi::c_void, u32) -> i32;
        let set_information: SetFileInformationByHandle = unsafe {
            std::mem::transmute(require_kernel32_api(b"SetFileInformationByHandle\0") as usize)
        };
        let path = r"C:\modern_invalid_file_information_class.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"unchanged".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        let information = [0u8; 16];
        let result = unsafe {
            set_information(
                handle,
                0x7fff,
                information.as_ptr().cast(),
                information.len() as u32,
            )
        };
        let error = super::native_get_last_error();
        let contents = context.lock().unwrap().fs.read_file(path).unwrap();
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert_eq!(result, 0);
        assert_eq!(error, 87); // ERROR_INVALID_PARAMETER
        assert_eq!(contents, b"unchanged");
    }

    #[test]
    fn nul_device_opens_as_character_sink_and_never_creates_a_disk_entry() {
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            if !ctx.fs.is_dir(r"C:\nul_device_unit") {
                ctx.fs.mkdir(r"C:\nul_device_unit").unwrap();
            }
        }
        let payload = b"discard this output";
        for path in [
            "NUL",
            r"C:\nul_device_unit\nul.txt",
            r"\\.\NUL",
            r"\\?\C:\nul_device_unit\NUL",
        ] {
            let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
            let handle = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0);
            assert_ne!(handle, u64::MAX, "failed to open {path}");
            assert_eq!(super::native_get_file_type(handle), 2, "{path}"); // FILE_TYPE_CHAR
            let mut written = 0;
            assert_eq!(
                super::native_write_file(
                    handle,
                    payload.as_ptr(),
                    payload.len() as u32,
                    &mut written,
                    0,
                ),
                1
            );
            assert_eq!(written as usize, payload.len());
            let mut read = u32::MAX;
            assert_eq!(
                super::native_read_file(handle, payload.as_ptr() as *mut u8, 8, &mut read, 0),
                1
            );
            assert_eq!(read, 0); // NUL reads as EOF.
            let mut size = -1;
            assert_eq!(super::native_get_file_size_ex(handle, &mut size), 1);
            assert_eq!(size, 0);
            assert_eq!(super::native_close_handle(handle), 1);
        }
        assert!(!context.lock().unwrap().fs.exists(r"C:\nul_device_unit\nul"));
    }

    #[test]
    fn console_devices_open_as_character_handles_and_serial_names_are_reserved() {
        for (path, access) in [
            ("CON", 0xC000_0000),
            ("CONIN$", 0x8000_0000),
            (r"\\.\CONOUT$", 0x4000_0000),
        ] {
            let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
            let handle = super::native_create_file_w(wide.as_ptr(), access, 7, 0, 3, 0, 0);
            assert_ne!(handle, u64::MAX, "failed to open {path}");
            assert_eq!(super::native_get_file_type(handle), 2, "{path}"); // FILE_TYPE_CHAR
            assert_eq!(super::native_close_handle(handle), 1);
        }

        for path in ["COM1", r"C:\nul_device_unit\LPT1.txt"] {
            let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
            assert_eq!(
                super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0),
                u64::MAX
            );
            assert_eq!(super::native_get_last_error(), 123); // ERROR_INVALID_NAME
        }
        assert!(!super::fs_ctx()
            .unwrap()
            .lock()
            .unwrap()
            .fs
            .exists(r"C:\nul_device_unit\LPT1.txt"));
    }

    #[test]
    fn create_file_rejects_unc_paths_with_bad_netpath() {
        for path in [r"\\server\share\x", r"\\?\UNC\server\share\x"] {
            let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
            assert_eq!(
                super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0),
                u64::MAX
            );
            assert_eq!(super::native_get_last_error(), 53); // ERROR_BAD_NETPATH
        }
    }

    #[test]
    fn create_file_rejects_invalid_names_and_stream_syntax() {
        for path in [r"C:\invalid|name", r"C:\file.txt:stream"] {
            let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
            assert_eq!(
                super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 2, 0, 0),
                u64::MAX
            );
            assert_eq!(super::native_get_last_error(), 123); // ERROR_INVALID_NAME
        }
    }

    #[test]
    fn modern_get_file_type_distinguishes_disk_handles_from_invalid_handles() {
        type GetFileType = unsafe extern "win64" fn(u64) -> u32;
        let get_file_type: GetFileType =
            unsafe { std::mem::transmute(require_kernel32_api(b"GetFileType\0") as usize) };
        let file_path = r"C:\modern_get_file_type.txt";
        let directory_path = r"C:\modern_get_file_type_directory";
        let file_wide = file_path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let directory_wide = directory_path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs.write_file(file_path, b"data".to_vec()).unwrap();
            ctx.fs.mkdir(directory_path).unwrap();
        }
        let file = super::native_create_file_w(file_wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        let directory = super::native_create_file_w(
            directory_wide.as_ptr(),
            0x8000_0000,
            7,
            0,
            3,
            0x0200_0000, // FILE_FLAG_BACKUP_SEMANTICS
            0,
        );
        assert_ne!(file, u64::MAX);
        assert_ne!(directory, u64::MAX);

        let file_type = unsafe { get_file_type(file) };
        let directory_type = unsafe { get_file_type(directory) };
        let invalid_type = unsafe { get_file_type(u64::MAX) };
        let invalid_error = super::native_get_last_error();
        assert_eq!(super::native_close_handle(directory), 1);
        assert_eq!(super::native_close_handle(file), 1);
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(file_path).unwrap();
        ctx.fs.rmdir(directory_path).unwrap();
        assert_eq!(file_type, 1); // FILE_TYPE_DISK
        assert_eq!(directory_type, 1); // directories are disk handles
        assert_eq!(invalid_type, 0); // FILE_TYPE_UNKNOWN
        assert_eq!(invalid_error, 6); // ERROR_INVALID_HANDLE
    }

    #[test]
    fn modern_get_file_size_ex_reports_null_output_and_invalid_handle() {
        type GetFileSizeEx = unsafe extern "win64" fn(u64, *mut i64) -> i32;
        let get_size: GetFileSizeEx =
            unsafe { std::mem::transmute(require_kernel32_api(b"GetFileSizeEx\0") as usize) };
        let path = r"C:\modern_get_file_size_ex_errors.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"size-data".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        let mut size = -1i64;
        let valid_result = unsafe { get_size(handle, &mut size) };
        let null_result = unsafe { get_size(handle, std::ptr::null_mut()) };
        let null_error = super::native_get_last_error();
        let invalid_result = unsafe { get_size(u64::MAX, &mut size) };
        let invalid_error = super::native_get_last_error();
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert_eq!(valid_result, 1);
        assert_eq!(size, 9);
        assert_eq!(null_result, 0);
        assert_eq!(null_error, 998); // ERROR_NOACCESS
        assert_eq!(invalid_result, 0);
        assert_eq!(invalid_error, 6); // ERROR_INVALID_HANDLE
    }

    #[test]
    fn modern_set_file_pointer_apis_update_position_and_extend_on_write() {
        type SetFilePointer = unsafe extern "win64" fn(u64, i32, *mut i32, u32) -> u32;
        type SetFilePointerEx = unsafe extern "win64" fn(u64, i64, *mut i64, u32) -> i32;
        let set_pointer: SetFilePointer =
            unsafe { std::mem::transmute(require_kernel32_api(b"SetFilePointer\0") as usize) };
        let set_pointer_ex: SetFilePointerEx =
            unsafe { std::mem::transmute(require_kernel32_api(b"SetFilePointerEx\0") as usize) };
        let path = r"C:\modern_set_file_pointer_apis.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"abc".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        assert_eq!(
            unsafe { set_pointer(handle, 5, std::ptr::null_mut(), 0) },
            5
        );
        let marker = b'X';
        let mut written = 0;
        assert_eq!(
            super::native_write_file(handle, &marker, 1, &mut written, 0),
            1
        );
        assert_eq!(written, 1);
        let mut position = -1i64;
        assert_eq!(unsafe { set_pointer_ex(handle, 0, &mut position, 2) }, 1);
        assert_eq!(position, 6);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"abc\0\0X"
        );
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_get_overlapped_result_reports_pending_complete_and_invalid() {
        type GetOverlappedResult = unsafe extern "win64" fn(u64, u64, *mut u32, i32) -> i32;
        let get_result: GetOverlappedResult =
            unsafe { std::mem::transmute(require_kernel32_api(b"GetOverlappedResult\0") as usize) };
        let path = r"C:\modern_get_overlapped_result.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"data".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let mut overlapped = [0u64; 4];
        let pointer = overlapped.as_mut_ptr() as u64;
        let mut transferred = 0;

        super::native_set_overlapped_status(pointer, super::STATUS_PENDING, 0);
        let pending = unsafe { get_result(handle, pointer, &mut transferred, 0) };
        let pending_error = super::native_get_last_error();
        super::native_set_overlapped_status(pointer, 0, 4);
        let completed = unsafe { get_result(handle, pointer, &mut transferred, 0) };
        let invalid = unsafe { get_result(u64::MAX, pointer, &mut transferred, 0) };
        let invalid_error = super::native_get_last_error();
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert_eq!(pending, 0);
        assert_eq!(pending_error, 996); // ERROR_IO_INCOMPLETE
        assert_eq!(completed, 1);
        assert_eq!(transferred, 4);
        assert_eq!(invalid, 0);
        assert_eq!(invalid_error, 6); // ERROR_INVALID_HANDLE
    }

    #[test]
    fn modern_get_overlapped_result_ex_returns_completed_byte_count() {
        type GetOverlappedResultEx = unsafe extern "win64" fn(u64, u64, *mut u32, u32, i32) -> i32;
        let get_result: GetOverlappedResultEx = unsafe {
            std::mem::transmute(require_kernel32_api(b"GetOverlappedResultEx\0") as usize)
        };
        let path = r"C:\modern_get_overlapped_result_ex.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"completed-data".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let mut overlapped = [0u64; 4];
        let pointer = overlapped.as_mut_ptr() as u64;
        super::native_set_overlapped_status(pointer, 0, 14);
        let mut transferred = 0;

        let result = unsafe { get_result(handle, pointer, &mut transferred, 0, 0) };
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert_eq!(result, 1);
        assert_eq!(transferred, 14);
    }

    #[test]
    fn modern_get_file_information_by_handle_reports_file_record() {
        type GetFileInformationByHandle = unsafe extern "win64" fn(u64, *mut u8) -> i32;
        let get_information: GetFileInformationByHandle = unsafe {
            std::mem::transmute(require_kernel32_api(b"GetFileInformationByHandle\0") as usize)
        };
        let path = r"C:\modern_file_information_by_handle.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"record".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let mut information = [0u8; 52];

        let result = unsafe { get_information(handle, information.as_mut_ptr()) };
        let invalid = unsafe { get_information(u64::MAX, information.as_mut_ptr()) };
        let null = unsafe { get_information(handle, std::ptr::null_mut()) };
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert_eq!(result, 1);
        assert_eq!(
            u32::from_le_bytes(information[..4].try_into().unwrap()),
            0x80
        );
        assert_eq!(
            u32::from_le_bytes(information[28..32].try_into().unwrap()),
            0x5743_4C49
        );
        assert_eq!(
            u32::from_le_bytes(information[36..40].try_into().unwrap()),
            6
        );
        assert_eq!(
            u32::from_le_bytes(information[40..44].try_into().unwrap()),
            1
        );
        assert_eq!(invalid, 0);
        assert_eq!(null, 0);
    }

    #[test]
    fn modern_ansi_hard_link_shares_source_contents() {
        type CreateHardLinkA = unsafe extern "win64" fn(*const u8, *const u8, u64) -> i32;
        let create_link: CreateHardLinkA =
            unsafe { std::mem::transmute(require_kernel32_api(b"CreateHardLinkA\0") as usize) };
        let source = b"C:\\modern_hard_link_ansi_source.txt\0";
        let link = b"C:\\modern_hard_link_ansi_alias.txt\0";
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(
                "C:\\modern_hard_link_ansi_source.txt",
                b"alias-data".to_vec(),
            )
            .unwrap();

        assert_eq!(unsafe { create_link(link.as_ptr(), source.as_ptr(), 0) }, 1);
        assert_eq!(
            context
                .lock()
                .unwrap()
                .fs
                .read_file("C:\\modern_hard_link_ansi_alias.txt")
                .unwrap(),
            b"alias-data"
        );
        let mut ctx = context.lock().unwrap();
        ctx.fs
            .delete_file("C:\\modern_hard_link_ansi_alias.txt")
            .unwrap();
        ctx.fs
            .delete_file("C:\\modern_hard_link_ansi_source.txt")
            .unwrap();
    }

    #[test]
    fn modern_symbolic_link_resolves_to_guest_target() {
        type CreateSymbolicLinkW = unsafe extern "win64" fn(*const u16, *const u16, u32) -> i32;
        let create_link: CreateSymbolicLinkW =
            unsafe { std::mem::transmute(require_kernel32_api(b"CreateSymbolicLinkW\0") as usize) };
        let target = r"C:\modern_symlink_target.txt";
        let link = r"C:\modern_symlink_alias.txt";
        let target_wide = target.encode_utf16().chain([0]).collect::<Vec<_>>();
        let link_wide = link.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(target, b"symlink-target".to_vec())
            .unwrap();

        assert_eq!(
            unsafe { create_link(link_wide.as_ptr(), target_wide.as_ptr(), 2) },
            1
        );
        assert_ne!(
            super::native_get_file_attributes_w(link_wide.as_ptr()) & 0x400,
            0
        );
        let handle = super::native_create_file_w(link_wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let mut bytes = [0u8; 14];
        let mut read = 0;
        assert_eq!(
            super::native_read_file(handle, bytes.as_mut_ptr(), 14, &mut read, 0),
            1
        );
        assert_eq!(&bytes, b"symlink-target");
        assert_eq!(super::native_close_handle(handle), 1);
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(link).unwrap();
        ctx.fs.delete_file(target).unwrap();
    }

    #[test]
    fn modern_ansi_file_attributes_toggle_readonly_state() {
        type SetFileAttributesA = unsafe extern "win64" fn(*const u8, u32) -> i32;
        let set_attributes: SetFileAttributesA =
            unsafe { std::mem::transmute(require_kernel32_api(b"SetFileAttributesA\0") as usize) };
        let path = b"C:\\modern_attributes_ansi.txt\0";
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file("C:\\modern_attributes_ansi.txt", b"attributes".to_vec())
            .unwrap();

        assert_eq!(unsafe { set_attributes(path.as_ptr(), 1) }, 1);
        let wide = "C:\\modern_attributes_ansi.txt"
            .encode_utf16()
            .chain([0])
            .collect::<Vec<_>>();
        assert_ne!(super::native_get_file_attributes_w(wide.as_ptr()) & 1, 0);
        assert_eq!(unsafe { set_attributes(path.as_ptr(), 0x80) }, 1);
        assert_eq!(super::native_delete_file_w(wide.as_ptr()), 1);
        assert!(!context
            .lock()
            .unwrap()
            .fs
            .exists("C:\\modern_attributes_ansi.txt"));
    }

    #[test]
    fn modern_ansi_create_and_enumerate_use_windows_1252_paths() {
        type CreateFileA = unsafe extern "win64" fn(*const u8, u32, u32, u64, u32, u32, u64) -> u64;
        let create_file: CreateFileA =
            unsafe { std::mem::transmute(require_kernel32_api(b"CreateFileA\0") as usize) };
        let mut path = b"C:\\modern_ansi_".to_vec();
        path.push(0x80); // Windows-1252 EURO SIGN
        path.extend_from_slice(b".txt\0");
        let wide_path = r"C:\modern_ansi_€.txt";
        let wide = wide_path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();

        let handle = unsafe { create_file(path.as_ptr(), 0xC000_0000, 7, 0, 1, 0, 0) };
        assert_ne!(handle, u64::MAX);
        let bytes = b"ansi-euro";
        let mut written = 0;
        assert_eq!(
            super::native_write_file(handle, bytes.as_ptr(), bytes.len() as u32, &mut written, 0),
            1
        );
        assert_eq!(written, bytes.len() as u32);
        assert_eq!(
            context.lock().unwrap().fs.read_file(wide_path).unwrap(),
            bytes
        );

        let mut find_data = [0u8; 320];
        let find = super::native_find_first_file_a(path.as_ptr(), find_data.as_mut_ptr());
        assert_ne!(find, u64::MAX);
        assert_eq!(&find_data[44..61], b"modern_ansi_\x80.txt");
        assert_eq!(super::native_find_close(find), 1);
        assert_eq!(super::native_close_handle(handle), 1);
        assert_eq!(super::native_delete_file_w(wide.as_ptr()), 1);
    }

    #[test]
    fn modern_wide_file_attributes_toggle_readonly_state() {
        type GetFileAttributesW = unsafe extern "win64" fn(*const u16) -> u32;
        type SetFileAttributesW = unsafe extern "win64" fn(*const u16, u32) -> i32;
        let get_attributes: GetFileAttributesW =
            unsafe { std::mem::transmute(require_kernel32_api(b"GetFileAttributesW\0") as usize) };
        let set_attributes: SetFileAttributesW =
            unsafe { std::mem::transmute(require_kernel32_api(b"SetFileAttributesW\0") as usize) };
        let path = r"C:\modern_attributes_wide.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"wide-attributes".to_vec())
            .unwrap();

        assert_eq!(unsafe { set_attributes(wide.as_ptr(), 0x3) }, 1);
        assert_eq!(unsafe { get_attributes(wide.as_ptr()) }, 0x3);
        assert_eq!(unsafe { set_attributes(wide.as_ptr(), 0x80) }, 1);
        assert_eq!(super::native_delete_file_w(wide.as_ptr()), 1);
        assert!(!context.lock().unwrap().fs.exists(path));
    }

    #[test]
    fn modern_get_file_attributes_ex_w_reports_file_and_missing_path() {
        type GetFileAttributesExW =
            unsafe extern "win64" fn(*const u16, i32, *mut std::ffi::c_void) -> i32;
        let get_attributes: GetFileAttributesExW = unsafe {
            std::mem::transmute(require_kernel32_api(b"GetFileAttributesExW\0") as usize)
        };
        let path = r"C:\modern_attributes_ex_wide.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let missing = r"C:\modern_attributes_ex_wide_missing.txt"
            .encode_utf16()
            .chain([0])
            .collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"metadata".to_vec())
            .unwrap();
        let mut data = [0u32; 9];

        assert_eq!(
            unsafe { get_attributes(wide.as_ptr(), 0, data.as_mut_ptr().cast()) },
            1
        );
        assert_eq!(data[0], 0x80);
        assert_eq!((data[7], data[8]), (0, 8));
        assert_eq!(
            unsafe { get_attributes(missing.as_ptr(), 0, data.as_mut_ptr().cast()) },
            0
        );
        assert_eq!(super::native_get_last_error(), 2); // ERROR_FILE_NOT_FOUND
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_ansi_find_first_file_returns_matching_name() {
        type FindFirstFileA = unsafe extern "win64" fn(*const u8, *mut std::ffi::c_void) -> u64;
        let find_first: FindFirstFileA =
            unsafe { std::mem::transmute(require_kernel32_api(b"FindFirstFileA\0") as usize) };
        let pattern = b"C:\\modern_find_ansi\\*.txt\0";
        let directory = r"C:\modern_find_ansi";
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs.mkdir(directory).unwrap();
            ctx.fs
                .write_file(r"C:\modern_find_ansi\wanted.txt", b"yes".to_vec())
                .unwrap();
            ctx.fs
                .write_file(r"C:\modern_find_ansi\ignored.bin", b"no".to_vec())
                .unwrap();
        }

        let mut data = [0u8; 320];
        let find = unsafe { find_first(pattern.as_ptr(), data.as_mut_ptr().cast()) };
        assert_ne!(find, u64::MAX);
        let name = unsafe {
            std::slice::from_raw_parts(data.as_ptr().add(44), 260)
                .iter()
                .copied()
                .take_while(|byte| *byte != 0)
                .collect::<Vec<_>>()
        };
        assert_eq!(name, b"wanted.txt");
        assert_eq!(super::native_find_close(find), 1);
        let mut ctx = context.lock().unwrap();
        ctx.fs
            .delete_file(r"C:\modern_find_ansi\wanted.txt")
            .unwrap();
        ctx.fs
            .delete_file(r"C:\modern_find_ansi\ignored.bin")
            .unwrap();
        ctx.fs.rmdir(directory).unwrap();
    }

    #[test]
    fn modern_set_end_of_file_truncates_and_extends_at_the_current_pointer() {
        type SetEndOfFile = unsafe extern "win64" fn(u64) -> i32;
        let set_end_of_file: SetEndOfFile =
            unsafe { std::mem::transmute(require_kernel32_api(b"SetEndOfFile\0") as usize) };
        let path = r"C:\modern_set_end_of_file.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"truncate-here".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let offset = 8i64;
        assert_eq!(
            super::native_set_file_pointer_ex(handle, offset, std::ptr::null_mut(), 0),
            1
        );

        assert_eq!(unsafe { set_end_of_file(handle) }, 1);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"truncate"
        );

        let extended_offset = 12i64;
        assert_eq!(
            super::native_set_file_pointer_ex(handle, extended_offset, std::ptr::null_mut(), 0),
            1
        );
        assert_eq!(unsafe { set_end_of_file(handle) }, 1);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"truncate\0\0\0\0"
        );
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_set_end_of_file_rejects_invalid_handle() {
        type SetEndOfFile = unsafe extern "win64" fn(u64) -> i32;
        let set_end_of_file: SetEndOfFile =
            unsafe { std::mem::transmute(require_kernel32_api(b"SetEndOfFile\0") as usize) };

        assert_eq!(unsafe { set_end_of_file(u64::MAX) }, 0);
        assert_eq!(super::native_get_last_error(), 6); // ERROR_INVALID_HANDLE
    }

    #[test]
    fn modern_flush_file_buffers_keeps_written_guest_bytes() {
        type FlushFileBuffers = unsafe extern "win64" fn(u64) -> i32;
        let flush: FlushFileBuffers =
            unsafe { std::mem::transmute(require_kernel32_api(b"FlushFileBuffers\0") as usize) };
        let path = r"C:\modern_flush_file_buffers.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"before-flush".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let replacement = b"after-flush!";
        let mut written = 0;
        assert_eq!(
            super::native_write_file(
                handle,
                replacement.as_ptr(),
                replacement.len() as u32,
                &mut written,
                0,
            ),
            1
        );
        assert_eq!(written as usize, replacement.len());
        assert_eq!(unsafe { flush(handle) }, 1);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            replacement
        );
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_get_overlapped_result_ex_rejects_invalid_file_handle() {
        type GetOverlappedResultEx =
            unsafe extern "win64" fn(u64, *mut std::ffi::c_void, *mut u32, u32, i32) -> i32;
        let get_result: GetOverlappedResultEx = unsafe {
            std::mem::transmute(require_kernel32_api(b"GetOverlappedResultEx\0") as usize)
        };
        let mut overlapped = [0u8; 32];
        let mut transferred = 0;
        assert_eq!(
            unsafe {
                get_result(
                    u64::MAX,
                    overlapped.as_mut_ptr().cast(),
                    &mut transferred,
                    0,
                    0,
                )
            },
            0
        );
        assert_eq!(super::native_get_last_error(), 6);
    }

    #[test]
    fn modern_ansi_temp_file_name_creates_a_unique_guest_file() {
        type GetTempPathA = unsafe extern "win64" fn(u32, *mut u8) -> u32;
        type GetTempFileNameA = unsafe extern "win64" fn(*const u8, *const u8, u32, *mut u8) -> u32;
        let get_temp_path: GetTempPathA =
            unsafe { std::mem::transmute(require_kernel32_api(b"GetTempPathA\0") as usize) };
        let get_temp_file: GetTempFileNameA =
            unsafe { std::mem::transmute(require_kernel32_api(b"GetTempFileNameA\0") as usize) };
        let mut directory = [0u8; 512];
        let length =
            unsafe { get_temp_path(directory.len() as u32, directory.as_mut_ptr()) } as usize;
        assert!(length > 0 && length < directory.len());
        assert_eq!(directory[length], 0);
        let prefix = b"wfs\0";
        let mut filename = [0u8; 1024];
        assert_ne!(
            unsafe {
                get_temp_file(
                    directory.as_ptr(),
                    prefix.as_ptr(),
                    0,
                    filename.as_mut_ptr(),
                )
            },
            0
        );
        let path = String::from_utf8(
            filename[..filename.iter().position(|byte| *byte == 0).unwrap()].to_vec(),
        )
        .unwrap();
        let context = super::fs_ctx().unwrap();
        assert!(context.lock().unwrap().fs.exists(&path));
        context.lock().unwrap().fs.delete_file(&path).unwrap();
    }

    #[test]
    fn modern_ansi_find_first_file_ex_covers_reference_options() {
        type FindFirstFileExA = unsafe extern "win64" fn(
            *const u8,
            i32,
            *mut std::ffi::c_void,
            i32,
            *const std::ffi::c_void,
            u32,
        ) -> u64;
        type FindNextFileA = unsafe extern "win64" fn(u64, *mut std::ffi::c_void) -> i32;
        let find_first: FindFirstFileExA =
            unsafe { std::mem::transmute(require_kernel32_api(b"FindFirstFileExA\0") as usize) };
        let find_next: FindNextFileA =
            unsafe { std::mem::transmute(require_kernel32_api(b"FindNextFileA\0") as usize) };
        let directory = r"C:\modern_find_ex_ansi";
        let pattern = b"C:\\modern_find_ex_ansi\\*\0";
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs.mkdir(directory).unwrap();
            ctx.fs.mkdir(r"C:\modern_find_ex_ansi\nested").unwrap();
            ctx.fs
                .write_file(r"C:\modern_find_ex_ansi\Alpha.txt", b"a".to_vec())
                .unwrap();
            ctx.fs
                .write_file(r"C:\modern_find_ex_ansi\beta.bin", b"b".to_vec())
                .unwrap();
        }

        for (info_level, search_op, flags) in [
            (0, 0, 0),
            (0, 0, 1),
            (0, 0, 2),
            (1, 0, 0),
            (0, 1, 0),
            (0, 1, 1),
            (0, 1, 2),
            (1, 1, 0),
        ] {
            let mut data = [0u8; 320];
            let find = unsafe {
                find_first(
                    pattern.as_ptr(),
                    info_level,
                    data.as_mut_ptr().cast(),
                    search_op,
                    std::ptr::null(),
                    flags,
                )
            };
            assert_ne!(find, u64::MAX, "{info_level}/{search_op}/{flags}");
            let mut names = Vec::new();
            loop {
                let name = unsafe {
                    std::slice::from_raw_parts(data.as_ptr().add(44), 260)
                        .iter()
                        .copied()
                        .take_while(|byte| *byte != 0)
                        .collect::<Vec<_>>()
                };
                names.push(String::from_utf8(name).unwrap());
                if unsafe { find_next(find, data.as_mut_ptr().cast()) } == 0 {
                    break;
                }
            }
            names.sort();
            assert_eq!(
                names,
                ["Alpha.txt", "beta.bin", "nested"],
                "{info_level}/{search_op}/{flags}"
            );
            assert_eq!(super::native_find_close(find), 1);
        }

        context.lock().unwrap().fs.remove(directory, true).unwrap();
    }

    #[test]
    fn modern_ansi_find_first_file_ex_reports_empty_missing_and_invalid_inputs() {
        type FindFirstFileExA = unsafe extern "win64" fn(
            *const u8,
            i32,
            *mut std::ffi::c_void,
            i32,
            *const std::ffi::c_void,
            u32,
        ) -> u64;
        let find_first: FindFirstFileExA =
            unsafe { std::mem::transmute(require_kernel32_api(b"FindFirstFileExA\0") as usize) };
        let directory = r"C:\modern_find_ex_ansi_failures";
        let empty_pattern = b"C:\\modern_find_ex_ansi_failures\\*\0";
        let missing_pattern = b"C:\\modern_find_ex_ansi_absent\\*\0";
        let context = super::fs_ctx().unwrap();
        context.lock().unwrap().fs.mkdir(directory).unwrap();
        let mut data = [0u8; 320];

        let empty = unsafe {
            find_first(
                empty_pattern.as_ptr(),
                0,
                data.as_mut_ptr().cast(),
                0,
                std::ptr::null(),
                0,
            )
        };
        let empty_error = super::native_get_last_error();
        let missing = unsafe {
            find_first(
                missing_pattern.as_ptr(),
                0,
                data.as_mut_ptr().cast(),
                0,
                std::ptr::null(),
                0,
            )
        };
        let missing_error = super::native_get_last_error();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(r"C:\modern_find_ex_ansi_failures\one.txt", b"x".to_vec())
            .unwrap();
        let invalid_output = unsafe {
            find_first(
                empty_pattern.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
                0,
            )
        };
        let invalid_output_error = super::native_get_last_error();
        let invalid_level = unsafe {
            find_first(
                empty_pattern.as_ptr(),
                99,
                data.as_mut_ptr().cast(),
                0,
                std::ptr::null(),
                0,
            )
        };
        let invalid_level_error = super::native_get_last_error();
        context.lock().unwrap().fs.remove(directory, true).unwrap();

        assert_eq!(empty, u64::MAX);
        assert_eq!(empty_error, 2); // ERROR_FILE_NOT_FOUND
        assert_eq!(missing, u64::MAX);
        assert_eq!(missing_error, 3); // ERROR_PATH_NOT_FOUND
        assert_eq!(invalid_output, u64::MAX);
        assert_eq!(invalid_output_error, 87); // ERROR_INVALID_PARAMETER
        assert_eq!(invalid_level, u64::MAX);
        assert_eq!(invalid_level_error, 87); // ERROR_INVALID_PARAMETER
    }

    #[test]
    fn modern_ansi_find_first_file_reports_empty_and_invalid_output() {
        type FindFirstFileA = unsafe extern "win64" fn(*const u8, *mut std::ffi::c_void) -> u64;
        let find_first: FindFirstFileA =
            unsafe { std::mem::transmute(require_kernel32_api(b"FindFirstFileA\0") as usize) };
        let directory = r"C:\modern_find_ansi_failures";
        let pattern = b"C:\\modern_find_ansi_failures\\*\0";
        let missing = b"C:\\modern_find_ansi_failures\\missing.txt\0";
        let context = super::fs_ctx().unwrap();
        context.lock().unwrap().fs.mkdir(directory).unwrap();
        let mut data = [0u8; 320];

        let empty = unsafe { find_first(pattern.as_ptr(), data.as_mut_ptr().cast()) };
        let empty_error = super::native_get_last_error();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(r"C:\modern_find_ansi_failures\entry.txt", b"x".to_vec())
            .unwrap();
        let invalid_output = unsafe { find_first(pattern.as_ptr(), std::ptr::null_mut()) };
        let invalid_output_error = super::native_get_last_error();
        let missing_result = unsafe { find_first(missing.as_ptr(), data.as_mut_ptr().cast()) };
        let missing_error = super::native_get_last_error();
        context.lock().unwrap().fs.remove(directory, true).unwrap();

        assert_eq!(empty, u64::MAX);
        assert_eq!(empty_error, 2); // ERROR_FILE_NOT_FOUND
        assert_eq!(invalid_output, u64::MAX);
        assert_eq!(invalid_output_error, 87); // ERROR_INVALID_PARAMETER
        assert_eq!(missing_result, u64::MAX);
        assert_eq!(missing_error, 2); // ERROR_FILE_NOT_FOUND
    }

    #[test]
    fn modern_ansi_symbolic_link_resolves_to_guest_target() {
        type CreateSymbolicLinkA = unsafe extern "win64" fn(*const u8, *const u8, u32) -> i32;
        let create_link: CreateSymbolicLinkA =
            unsafe { std::mem::transmute(require_kernel32_api(b"CreateSymbolicLinkA\0") as usize) };
        let target = b"C:\\modern_symlink_ansi_target.txt\0";
        let link = b"C:\\modern_symlink_ansi_alias.txt\0";
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(
                "C:\\modern_symlink_ansi_target.txt",
                b"ansi-target".to_vec(),
            )
            .unwrap();

        assert_eq!(unsafe { create_link(link.as_ptr(), target.as_ptr(), 2) }, 1);
        let link_wide = "C:\\modern_symlink_ansi_alias.txt"
            .encode_utf16()
            .chain([0])
            .collect::<Vec<_>>();
        assert_ne!(
            super::native_get_file_attributes_w(link_wide.as_ptr()) & 0x400,
            0
        );
        let handle = super::native_create_file_w(link_wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);
        let mut bytes = [0u8; 11];
        let mut read = 0;
        assert_eq!(
            super::native_read_file(handle, bytes.as_mut_ptr(), 11, &mut read, 0),
            1
        );
        assert_eq!(&bytes, b"ansi-target");
        assert_eq!(super::native_close_handle(handle), 1);
        let mut ctx = context.lock().unwrap();
        ctx.fs
            .delete_file("C:\\modern_symlink_ansi_alias.txt")
            .unwrap();
        ctx.fs
            .delete_file("C:\\modern_symlink_ansi_target.txt")
            .unwrap();
    }

    #[test]
    fn modern_open_file_by_id_rejects_invalid_volume_handle() {
        type OpenFileById = unsafe extern "win64" fn(
            u64,
            *const std::ffi::c_void,
            u32,
            u32,
            *const std::ffi::c_void,
            u32,
        ) -> u64;
        let open_by_id: OpenFileById =
            unsafe { std::mem::transmute(require_kernel32_api(b"OpenFileById\0") as usize) };
        let mut descriptor = [0u8; 24];
        descriptor[..4].copy_from_slice(&24u32.to_le_bytes());

        assert_eq!(
            unsafe {
                open_by_id(
                    u64::MAX,
                    descriptor.as_ptr().cast(),
                    0x8000_0000,
                    7,
                    std::ptr::null(),
                    0,
                )
            },
            u64::MAX
        );
        assert_eq!(super::native_get_last_error(), 6);
    }

    #[test]
    fn modern_set_file_valid_data_rejects_invalid_handle() {
        type SetFileValidData = unsafe extern "win64" fn(u64, i64) -> i32;
        let set_valid_data: SetFileValidData =
            unsafe { std::mem::transmute(require_kernel32_api(b"SetFileValidData\0") as usize) };
        assert_eq!(unsafe { set_valid_data(u64::MAX, 0) }, 0);
        assert_eq!(super::native_get_last_error(), 6);
    }

    #[test]
    fn modern_open_file_by_id_opens_existing_file_identifier() {
        type OpenFileById = unsafe extern "win64" fn(
            u64,
            *const std::ffi::c_void,
            u32,
            u32,
            *const std::ffi::c_void,
            u32,
        ) -> u64;
        let open_by_id: OpenFileById =
            unsafe { std::mem::transmute(require_kernel32_api(b"OpenFileById\0") as usize) };
        let path = r"C:\modern_open_by_id.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"opened-by-id".to_vec())
            .unwrap();
        let volume = super::native_create_file_w(
            [b'C' as u16, b':' as u16, b'\\' as u16, 0].as_ptr(),
            0,
            7,
            0,
            3,
            0x0200_0000, // FILE_FLAG_BACKUP_SEMANTICS
            0,
        );
        let file = super::native_create_file_w(wide.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        assert_ne!(volume, u64::MAX);
        assert_ne!(file, u64::MAX);
        let mut information = [0u8; 52];
        assert_eq!(
            super::native_get_file_information_by_handle(file, information.as_mut_ptr()),
            1
        );
        let file_id = u64::from_le_bytes([
            information[48],
            information[49],
            information[50],
            information[51],
            information[44],
            information[45],
            information[46],
            information[47],
        ]);
        let mut descriptor = [0u8; 24]; // FILE_ID_DESCRIPTOR
        descriptor[..4].copy_from_slice(&24u32.to_le_bytes());
        descriptor[4..8].copy_from_slice(&0u32.to_le_bytes()); // FileIdType
        descriptor[8..16].copy_from_slice(&file_id.to_le_bytes());

        let opened = unsafe {
            open_by_id(
                volume,
                descriptor.as_ptr().cast(),
                0x8000_0000,
                7,
                std::ptr::null(),
                0,
            )
        };
        let mut contents = [0u8; 12];
        let mut read = 0;
        let read_result = if opened != u64::MAX {
            super::native_read_file(opened, contents.as_mut_ptr(), 12, &mut read, 0)
        } else {
            0
        };
        if opened != u64::MAX {
            assert_eq!(super::native_close_handle(opened), 1);
        }
        assert_eq!(super::native_close_handle(file), 1);
        assert_eq!(super::native_close_handle(volume), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert_ne!(opened, u64::MAX);
        assert_eq!(read_result, 1);
        assert_eq!(read, 12);
        assert_eq!(&contents, b"opened-by-id");
    }

    #[test]
    fn modern_set_file_valid_data_reports_missing_volume_privilege() {
        type SetFileValidData = unsafe extern "win64" fn(u64, i64) -> i32;
        let set_valid_data: SetFileValidData =
            unsafe { std::mem::transmute(require_kernel32_api(b"SetFileValidData\0") as usize) };
        let path = r"C:\modern_set_valid_data_privilege.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"valid-data".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(wide.as_ptr(), 0x4000_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        let result = unsafe { set_valid_data(handle, 10) };
        let error = super::native_get_last_error();
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert_eq!(result, 0);
        assert_eq!(error, 1314); // ERROR_PRIVILEGE_NOT_HELD
    }

    #[test]
    fn modern_write_file_gather_writes_page_aligned_segment() {
        type WriteFileGather =
            unsafe extern "win64" fn(u64, *const u64, u32, *mut u32, *mut std::ffi::c_void) -> i32;
        let write_gather: WriteFileGather =
            unsafe { std::mem::transmute(require_kernel32_api(b"WriteFileGather\0") as usize) };
        let path = r"C:\modern_write_file_gather.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, vec![0; 4096])
            .unwrap();
        let handle = super::native_create_file_w(
            wide.as_ptr(),
            0xC000_0000,
            7,
            0,
            3,
            0x6000_0000, // FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED
            0,
        );
        assert_ne!(handle, u64::MAX);
        let layout = std::alloc::Layout::from_size_align(4096, 4096).unwrap();
        let page = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!page.is_null());
        unsafe { std::ptr::write_bytes(page, b'G', 4096) };
        let segments = [page as u64];
        let mut overlapped = [0u64; 4];
        let call_result = unsafe {
            write_gather(
                handle,
                segments.as_ptr(),
                4096,
                std::ptr::null_mut(),
                overlapped.as_mut_ptr().cast(),
            )
        };
        let call_error = super::native_get_last_error();
        let mut transferred = 0;
        let result = if call_result != 0 || call_error == 997 {
            super::native_get_overlapped_result(
                handle,
                overlapped.as_ptr() as u64,
                &mut transferred,
                1,
            )
        } else {
            0
        };
        let bytes = context
            .lock()
            .unwrap()
            .fs
            .read_file(path)
            .unwrap_or_default();
        unsafe { std::alloc::dealloc(page, layout) };
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert!(call_result != 0 || call_error == 997);
        assert_eq!(result, 1);
        assert_eq!(transferred, 4096);
        assert_eq!(bytes, vec![b'G'; 4096]);
    }

    #[test]
    fn modern_file_handle_completion_port_delivers_overlapped_write() {
        let path = r"C:\modern_file_handle_iocp.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, Vec::new())
            .unwrap();
        let handle = super::native_create_file_w(
            wide.as_ptr(),
            0xC000_0000,
            7,
            0,
            3,
            0x4000_0000, // FILE_FLAG_OVERLAPPED
            0,
        );
        assert_ne!(handle, u64::MAX);
        let key = 0x4f50_435f_4649_4c45;
        let port = super::native_create_io_completion_port(handle, 0, key, 0);
        assert_ne!(port, 0);

        let payload = vec![0x6du8; 64 * 1024];
        let mut overlapped = [0u64; 4];
        let pointer = overlapped.as_mut_ptr() as u64;
        let mut written = u32::MAX;
        let write_result = super::native_write_file(
            handle,
            payload.as_ptr(),
            payload.len() as u32,
            &mut written,
            pointer,
        );
        let write_error = super::native_get_last_error();
        let mut completion_bytes = 0;
        let mut completion_key = 0;
        let mut completion_overlapped = 0;
        let completion_result = super::native_get_queued_completion_status(
            port,
            &mut completion_bytes,
            &mut completion_key,
            &mut completion_overlapped,
            5000,
        );
        let mut completed_bytes = 0;
        let result_result =
            super::native_get_overlapped_result(handle, pointer, &mut completed_bytes, 0);
        unsafe { std::ptr::write_bytes(pointer as *mut u8, 0, 32) };
        let mut received = vec![0u8; payload.len()];
        let mut read = u32::MAX;
        let read_result = super::native_read_file(
            handle,
            received.as_mut_ptr(),
            received.len() as u32,
            &mut read,
            pointer,
        );
        let read_error = super::native_get_last_error();
        let mut read_completion_bytes = 0;
        let mut read_completion_key = 0;
        let mut read_completion_overlapped = 0;
        let read_completion_result = super::native_get_queued_completion_status(
            port,
            &mut read_completion_bytes,
            &mut read_completion_key,
            &mut read_completion_overlapped,
            5000,
        );
        let mut read_completed_bytes = 0;
        let read_result_result =
            super::native_get_overlapped_result(handle, pointer, &mut read_completed_bytes, 0);
        let contents = context
            .lock()
            .unwrap()
            .fs
            .read_file(path)
            .unwrap_or_default();
        assert_eq!(super::native_close_handle(handle), 1);
        assert_eq!(super::native_close_handle(port), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();

        assert_eq!(write_result, 0);
        assert_eq!(write_error, 997); // ERROR_IO_PENDING
        assert_eq!(completion_result, 1);
        assert_eq!(completion_bytes as usize, payload.len());
        assert_eq!(completion_key, key);
        assert_eq!(completion_overlapped, pointer);
        assert_eq!(result_result, 1);
        assert_eq!(completed_bytes as usize, payload.len());
        assert_eq!(contents, payload);
        assert_eq!(read_result, 0);
        assert_eq!(read_error, 997); // ERROR_IO_PENDING
        assert_eq!(read_completion_result, 1);
        assert_eq!(read_completion_bytes as usize, received.len());
        assert_eq!(read_completion_key, key);
        assert_eq!(read_completion_overlapped, pointer);
        assert_eq!(read_result_result, 1);
        assert_eq!(read_completed_bytes as usize, received.len());
        assert_eq!(received, payload);
    }

    #[test]
    fn modern_file_completion_modes_accept_overlapped_handle() {
        let path = r"C:\modern_file_completion_modes.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, Vec::new())
            .unwrap();
        let handle =
            super::native_create_file_w(wide.as_ptr(), 0x4000_0000, 7, 0, 3, 0x4000_0000, 0);
        assert_ne!(handle, u64::MAX);

        let result = super::native_set_file_completion_notification_modes(handle, 1);
        let error = super::native_get_last_error();
        assert_eq!(super::native_close_handle(handle), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert_eq!(result, 1, "valid overlapped file handle rejected: {error}");
    }

    #[test]
    fn modern_file_handle_cannot_be_associated_with_two_completion_ports() {
        let path = r"C:\modern_duplicate_file_iocp.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, Vec::new())
            .unwrap();
        let handle =
            super::native_create_file_w(wide.as_ptr(), 0x4000_0000, 7, 0, 3, 0x4000_0000, 0);
        assert_ne!(handle, u64::MAX);
        let first_port = super::native_create_io_completion_port(handle, 0, 0x1111, 0);
        assert_ne!(first_port, 0);

        let second_port = super::native_create_io_completion_port(handle, 0, 0x2222, 0);
        let error = super::native_get_last_error();
        assert_eq!(super::native_close_handle(handle), 1);
        assert_eq!(super::native_close_handle(first_port), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
        assert_eq!(second_port, 0);
        assert_eq!(error, 87); // ERROR_INVALID_PARAMETER
    }

    #[test]
    fn modern_ansi_file_mapping_view_commits_guest_file_changes() {
        type CreateFileMappingA =
            unsafe extern "win64" fn(u64, u64, u32, u32, u32, *const u8) -> u64;
        let create_mapping: CreateFileMappingA =
            unsafe { std::mem::transmute(require_kernel32_api(b"CreateFileMappingA\0") as usize) };
        let path = r"C:\modern_file_mapping_ansi.txt";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(path, b"abcdef".to_vec())
            .unwrap();
        let file = super::native_create_file_w(wide.as_ptr(), 0xC000_0000, 7, 0, 3, 0, 0);
        assert_ne!(file, u64::MAX);

        let mapping = unsafe { create_mapping(file, 0, 0x04, 0, 6, std::ptr::null()) };
        assert_ne!(mapping, 0);
        let view = super::native_map_view_of_file(mapping, 0x2, 0, 0, 6);
        assert!(!view.is_null());
        unsafe { view.add(2).write(b'Z') };
        assert_eq!(super::native_flush_view_of_file(view.cast(), 0), 1);
        assert_eq!(
            context.lock().unwrap().fs.read_file(path).unwrap(),
            b"abZdef"
        );
        assert_eq!(super::native_unmap_view_of_file(view.cast()), 1);
        assert_eq!(super::native_close_handle(mapping), 1);
        assert_eq!(super::native_close_handle(file), 1);
        context.lock().unwrap().fs.delete_file(path).unwrap();
    }

    #[test]
    fn modern_ansi_replace_file_moves_old_data_to_backup() {
        type ReplaceFileA =
            unsafe extern "win64" fn(*const u8, *const u8, *const u8, u32, u64, u64) -> i32;
        let replace: ReplaceFileA =
            unsafe { std::mem::transmute(require_kernel32_api(b"ReplaceFileA\0") as usize) };
        let destination = b"C:\\modern_replace_ansi_destination.txt\0";
        let replacement = b"C:\\modern_replace_ansi_new.txt\0";
        let backup = b"C:\\modern_replace_ansi_backup.txt\0";
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs
                .write_file(
                    "C:\\modern_replace_ansi_destination.txt",
                    b"old-ansi".to_vec(),
                )
                .unwrap();
            ctx.fs
                .write_file("C:\\modern_replace_ansi_new.txt", b"new-ansi".to_vec())
                .unwrap();
        }

        assert_eq!(
            unsafe {
                replace(
                    destination.as_ptr(),
                    replacement.as_ptr(),
                    backup.as_ptr(),
                    0,
                    0,
                    0,
                )
            },
            1
        );
        let ctx = context.lock().unwrap();
        assert_eq!(
            ctx.fs
                .read_file("C:\\modern_replace_ansi_destination.txt")
                .unwrap(),
            b"new-ansi"
        );
        assert_eq!(
            ctx.fs
                .read_file("C:\\modern_replace_ansi_backup.txt")
                .unwrap(),
            b"old-ansi"
        );
        assert!(!ctx.fs.exists("C:\\modern_replace_ansi_new.txt"));
        drop(ctx);
        let mut ctx = context.lock().unwrap();
        ctx.fs
            .delete_file("C:\\modern_replace_ansi_backup.txt")
            .unwrap();
        ctx.fs
            .delete_file("C:\\modern_replace_ansi_destination.txt")
            .unwrap();
    }

    #[test]
    fn modern_ansi_remove_directory_removes_empty_guest_directory() {
        type RemoveDirectoryA = unsafe extern "win64" fn(*const u8) -> i32;
        let remove_directory: RemoveDirectoryA =
            unsafe { std::mem::transmute(require_kernel32_api(b"RemoveDirectoryA\0") as usize) };
        let path = b"C:\\modern_remove_directory_ansi\0";
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .mkdir("C:\\modern_remove_directory_ansi")
            .unwrap();

        assert_eq!(unsafe { remove_directory(path.as_ptr()) }, 1);
        assert!(!context
            .lock()
            .unwrap()
            .fs
            .exists("C:\\modern_remove_directory_ansi"));
    }

    #[test]
    fn modern_write_file_gather_rejects_invalid_handle() {
        type WriteFileGather =
            unsafe extern "win64" fn(u64, *const u64, u32, *mut u32, *mut std::ffi::c_void) -> i32;
        let write_gather: WriteFileGather =
            unsafe { std::mem::transmute(require_kernel32_api(b"WriteFileGather\0") as usize) };
        let layout = std::alloc::Layout::from_size_align(4096, 4096).unwrap();
        let page = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!page.is_null());
        let segments = [page as u64];
        let mut overlapped = [0u8; 32];
        let result = unsafe {
            write_gather(
                u64::MAX,
                segments.as_ptr(),
                4096,
                std::ptr::null_mut(),
                overlapped.as_mut_ptr().cast(),
            )
        };
        unsafe { std::alloc::dealloc(page, layout) };
        assert_eq!(result, 0);
        assert_eq!(super::native_get_last_error(), 6);
    }

    #[test]
    fn modern_copy_file_w_copies_guest_data_and_preserves_source() {
        type CopyFileW = unsafe extern "win64" fn(*const u16, *const u16, i32) -> i32;
        let copy_file: CopyFileW =
            unsafe { std::mem::transmute(require_kernel32_api(b"CopyFileW\0") as usize) };
        let source = r"C:\modern_copy_w_source.txt";
        let destination = r"C:\modern_copy_w_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let destination_wide = destination.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(source, b"wide-copy-data".to_vec())
            .unwrap();

        assert_eq!(
            unsafe { copy_file(source_wide.as_ptr(), destination_wide.as_ptr(), 1) },
            1
        );
        let ctx = context.lock().unwrap();
        assert_eq!(ctx.fs.read_file(destination).unwrap(), b"wide-copy-data");
        assert_eq!(ctx.fs.read_file(source).unwrap(), b"wide-copy-data");
        drop(ctx);
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(destination).unwrap();
        ctx.fs.delete_file(source).unwrap();
    }

    #[test]
    fn modern_copy_file_w_preserves_existing_destination_when_fail_set() {
        type CopyFileW = unsafe extern "win64" fn(*const u16, *const u16, i32) -> i32;
        let copy_file: CopyFileW =
            unsafe { std::mem::transmute(require_kernel32_api(b"CopyFileW\0") as usize) };
        let source = r"C:\modern_copy_w_conflict_source.txt";
        let destination = r"C:\modern_copy_w_conflict_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let destination_wide = destination.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs
                .write_file(source, b"source-content".to_vec())
                .unwrap();
            ctx.fs
                .write_file(destination, b"keep-content".to_vec())
                .unwrap();
        }

        let result = unsafe { copy_file(source_wide.as_ptr(), destination_wide.as_ptr(), 1) };
        let source_bytes = context.lock().unwrap().fs.read_file(source).unwrap();
        let destination_bytes = context.lock().unwrap().fs.read_file(destination).unwrap();
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(destination).unwrap();
        ctx.fs.delete_file(source).unwrap();
        assert_eq!(result, 0);
        assert_eq!(source_bytes, b"source-content");
        assert_eq!(destination_bytes, b"keep-content");
    }

    #[test]
    fn modern_set_file_information_by_handle_renames_guest_file() {
        type SetFileInformationByHandle =
            unsafe extern "win64" fn(u64, i32, *const std::ffi::c_void, u32) -> i32;
        let set_information: SetFileInformationByHandle = unsafe {
            std::mem::transmute(require_kernel32_api(b"SetFileInformationByHandle\0") as usize)
        };
        let source = r"C:\modern_rename_by_handle_source.txt";
        let destination = r"C:\modern_rename_by_handle_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        context
            .lock()
            .unwrap()
            .fs
            .write_file(source, b"rename-by-handle".to_vec())
            .unwrap();
        let handle = super::native_create_file_w(source_wide.as_ptr(), 0xC001_0000, 7, 0, 3, 0, 0);
        assert_ne!(handle, u64::MAX);

        let encoded = destination.encode_utf16().collect::<Vec<_>>();
        let mut information = vec![0u8; 20 + encoded.len() * 2];
        information[16..20].copy_from_slice(&((encoded.len() * 2) as u32).to_le_bytes());
        for (index, unit) in encoded.iter().enumerate() {
            information[20 + index * 2..22 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(
            unsafe {
                set_information(
                    handle,
                    3, // FileRenameInfo
                    information.as_ptr().cast(),
                    information.len() as u32,
                )
            },
            1
        );
        assert_eq!(
            context.lock().unwrap().fs.read_file(destination).unwrap(),
            b"rename-by-handle"
        );
        assert!(!context.lock().unwrap().fs.exists(source));
        assert_eq!(super::native_close_handle(handle), 1);
    }

    #[test]
    fn modern_move_file_ex_replaces_existing_guest_destination() {
        type MoveFileExW = unsafe extern "win64" fn(*const u16, *const u16, u32) -> i32;
        let move_file: MoveFileExW =
            unsafe { std::mem::transmute(require_kernel32_api(b"MoveFileExW\0") as usize) };
        let source = r"C:\modern_move_ex_source.txt";
        let destination = r"C:\modern_move_ex_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let destination_wide = destination.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs
                .write_file(source, b"new-destination".to_vec())
                .unwrap();
            ctx.fs
                .write_file(destination, b"old-destination".to_vec())
                .unwrap();
        }

        assert_eq!(
            unsafe { move_file(source_wide.as_ptr(), destination_wide.as_ptr(), 1) },
            1
        );
        let ctx = context.lock().unwrap();
        assert!(!ctx.fs.exists(source));
        assert_eq!(ctx.fs.read_file(destination).unwrap(), b"new-destination");
        drop(ctx);
        context.lock().unwrap().fs.delete_file(destination).unwrap();
    }

    #[test]
    fn modern_move_file_ex_preserves_existing_paths_without_replace_flag() {
        type MoveFileExW = unsafe extern "win64" fn(*const u16, *const u16, u32) -> i32;
        let move_file: MoveFileExW =
            unsafe { std::mem::transmute(require_kernel32_api(b"MoveFileExW\0") as usize) };
        let source = r"C:\modern_move_ex_conflict_source.txt";
        let destination = r"C:\modern_move_ex_conflict_destination.txt";
        let source_wide = source.encode_utf16().chain([0]).collect::<Vec<_>>();
        let destination_wide = destination.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();
        {
            let mut ctx = context.lock().unwrap();
            ctx.fs
                .write_file(source, b"source-content".to_vec())
                .unwrap();
            ctx.fs
                .write_file(destination, b"keep-content".to_vec())
                .unwrap();
        }

        let result = unsafe { move_file(source_wide.as_ptr(), destination_wide.as_ptr(), 0) };
        let error = super::native_get_last_error();
        let ctx = context.lock().unwrap();
        assert_eq!(ctx.fs.read_file(source).unwrap(), b"source-content");
        assert_eq!(ctx.fs.read_file(destination).unwrap(), b"keep-content");
        drop(ctx);
        let mut ctx = context.lock().unwrap();
        ctx.fs.delete_file(destination).unwrap();
        ctx.fs.delete_file(source).unwrap();
        assert_eq!(result, 0);
        assert_eq!(error, 183); // ERROR_ALREADY_EXISTS
    }

    #[test]
    fn modern_wide_directory_apis_create_and_remove_guest_directory() {
        type CreateDirectoryW =
            unsafe extern "win64" fn(*const u16, *const std::ffi::c_void) -> i32;
        type RemoveDirectoryW = unsafe extern "win64" fn(*const u16) -> i32;
        let create_directory: CreateDirectoryW =
            unsafe { std::mem::transmute(require_kernel32_api(b"CreateDirectoryW\0") as usize) };
        let remove_directory: RemoveDirectoryW =
            unsafe { std::mem::transmute(require_kernel32_api(b"RemoveDirectoryW\0") as usize) };
        let path = r"C:\modern_directory_api";
        let wide = path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let context = super::fs_ctx().unwrap();

        assert_eq!(
            unsafe { create_directory(wide.as_ptr(), std::ptr::null()) },
            1
        );
        assert!(context.lock().unwrap().fs.exists(path));
        assert_eq!(unsafe { remove_directory(wide.as_ptr()) }, 1);
        assert!(!context.lock().unwrap().fs.exists(path));
    }

    #[test]
    fn initializes_critical_section_with_spin_count() {
        let mut section = [0x5au8; 40];
        assert_eq!(
            native_initialize_critical_section_and_spin_count(section.as_mut_ptr(), 4000),
            1
        );
        assert_eq!(section, [0; 40]);
        assert_eq!(
            native_initialize_critical_section_and_spin_count(std::ptr::null_mut(), 0),
            0
        );
    }

    #[test]
    fn pointer_encoding_round_trips_null_and_non_null_values() {
        for value in [0, 1, 0x1234_5678_9abc_def0] {
            let encoded = native_encode_pointer(value);
            assert_ne!(encoded, value);
            assert_eq!(native_decode_pointer(encoded), value);
        }
    }

    #[test]
    fn tracks_exact_native_heap_sizes_and_rejects_freed_blocks() {
        let ptr = super::native_heap_alloc(super::PROCESS_HEAP_HANDLE, 0x8, 3);
        assert_ne!(ptr, 0);
        assert_eq!(native_heap_size(super::PROCESS_HEAP_HANDLE, 0, ptr), 3);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(ptr as *const u8, 3) },
            &[0, 0, 0]
        );
        let grown = native_heap_realloc(super::PROCESS_HEAP_HANDLE, 0x8, ptr, 9);
        assert_ne!(grown, 0);
        assert_eq!(native_heap_size(super::PROCESS_HEAP_HANDLE, 0, grown), 9);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(grown as *const u8, 9) },
            &[0; 9]
        );
        assert_eq!(native_heap_free(super::PROCESS_HEAP_HANDLE, 0, grown), 1);
        assert_eq!(
            native_heap_size(super::PROCESS_HEAP_HANDLE, 0, grown),
            usize::MAX
        );
        assert_eq!(native_heap_free(super::PROCESS_HEAP_HANDLE, 0, grown), 0);
    }

    #[test]
    fn initializes_srw_lock_to_unlocked_state() {
        let mut lock = u64::MAX;
        native_initialize_srw_lock(&mut lock);
        assert_eq!(lock, 0);
        native_initialize_srw_lock(std::ptr::null_mut());
    }

    #[test]
    fn srw_lock_blocks_shared_try_while_exclusive_is_held() {
        let mut lock = 0u64;
        native_initialize_srw_lock(&mut lock);
        native_acquire_srw_lock_exclusive(&mut lock);
        assert_eq!(native_try_acquire_srw_lock_shared(&mut lock), 0);
        native_release_srw_lock_exclusive(&mut lock);
        assert_eq!(native_try_acquire_srw_lock_shared(&mut lock), 1);
        native_release_srw_lock_shared(&mut lock);
    }

    #[test]
    fn processor_feature_query_reports_host_isa_and_rejects_unknown_ids() {
        assert_eq!(native_is_processor_feature_present(10), 1); // SSE2 is required by x86-64
        assert_eq!(
            native_is_processor_feature_present(40),
            std::is_x86_feature_detected!("avx2") as i32
        );
        assert_eq!(native_is_processor_feature_present(999), 0);
    }

    #[test]
    fn ntdll_version_and_status_translation_report_windows_baseline() {
        let mut info = [0u8; 276];
        info[..4].copy_from_slice(&276u32.to_le_bytes());
        assert_eq!(native_rtl_get_version(info.as_mut_ptr()), 0);
        assert_eq!(u32::from_le_bytes(info[4..8].try_into().unwrap()), 10);
        assert_eq!(u32::from_le_bytes(info[12..16].try_into().unwrap()), 19045);
        info[..4].copy_from_slice(&275u32.to_le_bytes());
        assert_eq!(native_rtl_get_version(info.as_mut_ptr()), 0xC000_000D);
        assert_eq!(native_rtl_nt_status_to_dos_error(0xC000_0022), 5);
        assert_eq!(native_rtl_nt_status_to_dos_error(0xC000_0120), 995);
        assert_eq!(native_rtl_nt_status_to_dos_error(0xC000_014B), 109);
        assert_eq!(native_rtl_nt_status_to_dos_error(0xDEAD_BEEF), 317);
    }

    #[test]
    fn condition_wait_releases_and_reacquires_exclusive_srw_lock() {
        let mut lock = 0u64;
        let mut condition = 0u64;
        native_initialize_srw_lock(&mut lock);
        native_initialize_condition_variable(&mut condition);
        native_acquire_srw_lock_exclusive(&mut lock);
        assert_eq!(
            native_sleep_condition_variable_srw(&mut condition, &mut lock, 0, 0),
            0
        );
        assert_eq!(native_try_acquire_srw_lock_shared(&mut lock), 0);
        let condition_address = (&mut condition as *mut u64) as usize;
        let worker = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(5));
            native_wake_all_condition_variable(condition_address as *mut u64);
        });
        assert_eq!(
            native_sleep_condition_variable_srw(&mut condition, &mut lock, 1000, 0),
            1
        );
        native_release_srw_lock_exclusive(&mut lock);
        worker.join().unwrap();
    }

    #[test]
    fn init_once_retries_failed_callback_and_caches_context() {
        extern "win64" fn callback(_once: *mut u64, parameter: u64, context: *mut u64) -> i32 {
            let calls = unsafe { &*(parameter as *const std::sync::atomic::AtomicU32) };
            if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                return 0;
            }
            unsafe { context.write(0x1234) };
            1
        }
        let calls = std::sync::atomic::AtomicU32::new(0);
        let mut once = 0u64;
        let mut context = 0u64;
        let param = (&calls as *const std::sync::atomic::AtomicU32) as u64;
        let cb = callback as *const () as usize as u64;
        assert_eq!(
            native_init_once_execute_once(&mut once, cb, param, &mut context),
            0
        );
        assert_eq!(
            native_init_once_execute_once(&mut once, cb, param, &mut context),
            1
        );
        assert_eq!(context, 0x1234);
        context = 0;
        assert_eq!(
            native_init_once_execute_once(&mut once, cb, param, &mut context),
            1
        );
        assert_eq!(context, 0x1234);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn validates_native_memory_status_buffer_length() {
        assert_eq!(native_global_memory_status_ex(std::ptr::null_mut()), 0);
        let mut status = NativeMemoryStatus {
            length: 63,
            load: 0,
            total_physical: 0,
            available_physical: 0,
            total_page_file: 0,
            available_page_file: 0,
            total_virtual: 0,
            available_virtual: 0,
            available_extended_virtual: 0,
        };
        assert_eq!(native_global_memory_status_ex(&mut status), 0);
        assert_eq!(status.total_physical, 0);
        status.length = 64;
        assert_eq!(native_global_memory_status_ex(&mut status), 1);
        assert_eq!(status.total_physical, 512 * 1024 * 1024);
        assert_eq!(status.available_physical, 256 * 1024 * 1024);
    }

    #[test]
    fn exposes_the_windows_current_thread_pseudo_handle() {
        assert_eq!(native_get_current_thread(), u64::MAX - 1);
    }

    #[test]
    fn reports_a_distinct_id_for_each_native_guest_thread() {
        assert_eq!(native_get_current_thread_id(), 1);
        let worker = std::thread::spawn(|| {
            THREAD_NATIVE_HANDLE.with(|handle| handle.set(0xface));
            native_get_current_thread_id()
        });
        assert_eq!(worker.join().unwrap(), 0xface);
    }

    #[test]
    fn writes_the_x64_process_information_layout() {
        let mut info = [0u8; 24];
        assert!(write_process_information(
            info.as_mut_ptr() as u64,
            0x6000,
            0x6100,
            42
        ));
        assert_eq!(u64::from_le_bytes(info[..8].try_into().unwrap()), 0x6000);
        assert_eq!(u64::from_le_bytes(info[8..16].try_into().unwrap()), 0x6100);
        assert_eq!(u32::from_le_bytes(info[16..20].try_into().unwrap()), 42);
        assert_eq!(u32::from_le_bytes(info[20..24].try_into().unwrap()), 1);
        assert!(!write_process_information(0, 0, 0, 0));
    }

    #[test]
    fn exposes_a_process_owned_id_and_active_exit_status() {
        let process = native_get_current_process();
        assert_eq!(process, u64::MAX);
        assert_eq!(native_get_current_process_id(), 1);
        let mut exit_code = 0;
        assert_eq!(native_get_exit_code_process(process, &mut exit_code), 1);
        assert_eq!(exit_code, 259); // STILL_ACTIVE
    }

    #[test]
    fn rejects_invalid_process_queries_and_pseudo_handle_closes() {
        native_set_last_error(0);
        let mut exit_code = 0;
        assert_eq!(native_get_exit_code_process(0x1234, &mut exit_code), 0);
        assert_eq!(native_get_last_error(), 6); // ERROR_INVALID_HANDLE
        assert_eq!(native_close_handle(native_get_current_process()), 0);
        assert_eq!(native_get_last_error(), 6);
    }

    #[test]
    fn owns_child_process_handles_until_explicit_close() {
        let process = process_ctx().unwrap();
        let (handle, thread_handle, child) = process
            .children
            .lock()
            .unwrap()
            .allocate(process.process_id);
        assert_eq!(child.parent_process_id, 1);
        assert_ne!(handle, thread_handle);
        assert!(child.process_id >= 2);
        let mut exit_code = 0;
        assert_eq!(native_get_exit_code_process(handle, &mut exit_code), 1);
        assert_eq!(exit_code, 259); // STILL_ACTIVE
        assert_eq!(native_wait_for_single_object(handle, 0), 258); // WAIT_TIMEOUT
        assert_eq!(native_wait_for_single_object(thread_handle, 0), 258); // WAIT_TIMEOUT
        assert_eq!(native_terminate_process(handle, 23), 1);
        assert_eq!(native_wait_for_single_object(handle, 0), 0);
        assert_eq!(native_wait_for_single_object(thread_handle, 0), 0);
        assert_eq!(native_get_exit_code_process(handle, &mut exit_code), 1);
        assert_eq!(exit_code, 23);
        assert_eq!(native_close_handle(handle), 1);
        assert_eq!(native_get_exit_code_process(handle, &mut exit_code), 0);
        assert_eq!(
            native_get_exit_code_process(thread_handle, &mut exit_code),
            1
        );
        assert_eq!(exit_code, 23);
        assert_eq!(native_close_handle(thread_handle), 1);
    }

    #[test]
    fn terminate_process_signals_a_launched_host_child() {
        let process = process_ctx().unwrap();
        let (handle, _, child) = process
            .children
            .lock()
            .unwrap()
            .allocate(process.process_id);
        let pid = unsafe { super::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                super::pause();
                _exit(0);
            }
        }
        child
            .host_pid
            .store(pid, std::sync::atomic::Ordering::Release);
        assert_eq!(native_terminate_process(handle, 23), 1);
        assert_eq!(*child.termination_code.lock().unwrap(), Some(23));
        let mut status = 0;
        assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status & 0x7f, 15);
        assert_eq!(native_close_handle(handle), 1);
    }

    #[test]
    fn parses_quoted_create_process_command_lines() {
        assert_eq!(
            parse_windows_command_line(r#"  "C:\Program Files\tool.exe" --flag "two words""#)
                .unwrap(),
            [r"C:\Program Files\tool.exe", "--flag", "two words"]
        );
        assert_eq!(
            parse_windows_command_line(r#"tool.exe "a\"b""#).unwrap(),
            ["tool.exe", "a\"b"]
        );
        assert!(parse_windows_command_line("\"unterminated").is_err());
    }

    #[test]
    fn parses_a_unicode_child_environment_block() {
        let block: Vec<u16> = "Path=one\0NAME=value\0\0".encode_utf16().collect();
        assert_eq!(
            environment_block(block.as_ptr() as u64).unwrap(),
            [
                ("Path".to_string(), "one".to_string()),
                ("NAME".to_string(), "value".to_string())
            ]
        );
        let invalid: Vec<u16> = "missing-equals\0\0".encode_utf16().collect();
        assert_eq!(environment_block(invalid.as_ptr() as u64), Err(87));
    }

    #[test]
    fn derives_create_process_target_and_validates_working_directory() {
        let mut fs = WinFs::new();
        fs.mkdir(r"C:\work").unwrap();
        let launch = native_launch_spec(
            None,
            Some(r#""C:\tools\child.exe" --check"#.to_string()),
            Some(r"C:\work".to_string()),
            &fs,
        )
        .unwrap();
        assert_eq!(launch.application, r"C:\tools\child.exe");
        assert_eq!(launch.arguments, [r"C:\tools\child.exe", "--check"]);
        assert_eq!(launch.current_directory, r"C:\work");
        assert_eq!(
            native_launch_spec(Some(String::new()), None, None, &fs),
            Err(87)
        );
        assert_eq!(
            native_launch_spec(
                Some(r"C:\child.exe".to_string()),
                None,
                Some(r"C:\missing".to_string()),
                &fs,
            ),
            Err(267)
        );
    }

    #[test]
    fn loads_child_pe_images_only_from_the_guest_filesystem() {
        let mut fs = WinFs::new();
        fs.write_file(r"C:\child.exe", crate::pe::builder::hello("child"))
            .unwrap();
        let launch =
            native_launch_spec(Some(r"C:\child.exe".to_string()), None, None, &fs).unwrap();
        assert!(!load_native_child_image(&fs, &launch)
            .unwrap()
            .image
            .is_empty());
        assert_eq!(
            load_native_child_image(
                &fs,
                &NativeLaunchSpec {
                    application: r"C:\missing.exe".to_string(),
                    arguments: vec![],
                    current_directory: r"C:\".to_string(),
                },
            )
            .unwrap_err(),
            2
        );
        fs.write_file(r"C:\bad.exe", b"not a PE".to_vec()).unwrap();
        let invalid = native_launch_spec(Some(r"C:\bad.exe".to_string()), None, None, &fs).unwrap();
        assert_eq!(load_native_child_image(&fs, &invalid).unwrap_err(), 193);
    }

    #[test]
    fn create_process_rejects_missing_output_record_before_launching() {
        let mut application: Vec<u16> = r"C:\child.exe"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        native_set_last_error(0);
        assert_eq!(
            native_create_process_w(
                application.as_mut_ptr(),
                std::ptr::null_mut(),
                0,
                0,
                0,
                0,
                0,
                std::ptr::null(),
                0,
                0,
            ),
            0
        );
        assert_eq!(native_get_last_error(), 87); // ERROR_INVALID_PARAMETER
    }

    #[test]
    fn resolves_the_kernel32_ansi_module_handle() {
        assert_eq!(
            native_get_module_handle_a(b"kernel32\0".as_ptr()),
            API_SET_MODULE
        );
        assert_eq!(native_get_module_handle_a(b"user32\0".as_ptr()), 0);
    }

    #[test]
    fn reallocates_process_heap_memory_without_losing_contents() {
        let allocation = native_heap_alloc(super::PROCESS_HEAP_HANDLE, 0, 4);
        assert_ne!(allocation, 0);
        unsafe { std::ptr::copy_nonoverlapping(b"rg!\0".as_ptr(), allocation as *mut u8, 4) };
        let grown = native_heap_realloc(super::PROCESS_HEAP_HANDLE, 0, allocation, 8);
        assert_ne!(grown, 0);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(grown as *const u8, 4) },
            b"rg!\0"
        );
        assert_eq!(native_heap_free(super::PROCESS_HEAP_HANDLE, 0, grown), 1);
    }

    #[test]
    fn fills_process_prng_output() {
        let mut output = [0; 16];
        assert_eq!(native_process_prng(output.as_mut_ptr(), output.len()), 1);
        assert!(output.iter().any(|byte| *byte != 0));
        assert_eq!(native_process_prng(std::ptr::null_mut(), 1), 0);
    }

    #[test]
    fn reports_a_basic_console_mode_for_standard_output() {
        let mut mode = 0;
        assert_eq!(native_get_console_mode(1, &mut mode), 1);
        assert_eq!(mode, 1);
        assert_eq!(native_get_console_mode(99, &mut mode), 0);
        assert_eq!(native_get_console_mode(1, std::ptr::null_mut()), 0);
    }

    #[test]
    fn reports_the_native_console_output_code_page() {
        assert_eq!(native_get_console_output_cp(), 1252);
    }

    #[test]
    fn zero_byte_write_succeeds_for_a_native_standard_handle() {
        let mut written = u32::MAX;
        assert_eq!(
            super::native_write_file(0x5000_0002, std::ptr::null(), 0, &mut written, 0,),
            1
        );
        assert_eq!(written, 0);
    }

    #[test]
    fn accepts_timestamp_updates_on_native_standard_handles() {
        assert_eq!(
            native_set_file_time(1, std::ptr::null(), std::ptr::null(), std::ptr::null()),
            1
        );
        assert_eq!(
            native_set_file_time(99, std::ptr::null(), std::ptr::null(), std::ptr::null()),
            0
        );
    }

    #[test]
    fn rejects_console_writes_to_non_console_handles() {
        assert_eq!(
            native_write_console_w(99, std::ptr::null(), 0, std::ptr::null_mut(), 0),
            0
        );
    }

    #[test]
    fn reports_missing_variables_from_the_empty_native_environment() {
        native_set_last_error(0);
        let name = ['R' as u16, 0];
        assert_eq!(
            native_get_environment_variable_w(name.as_ptr(), std::ptr::null_mut(), 0),
            0
        );
        assert_eq!(native_get_last_error(), 203);
    }

    #[test]
    fn sets_reads_and_removes_a_guest_environment_variable() {
        let name: Vec<u16> = "WINRUN_TEST_NODE_ENV"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let value: Vec<u16> = "node-value"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        assert_eq!(
            native_set_environment_variable_w(name.as_ptr(), value.as_ptr()),
            1
        );
        let mut output = [0u16; 16];
        assert_eq!(
            native_get_environment_variable_w(
                name.as_ptr(),
                output.as_mut_ptr(),
                output.len() as u32
            ),
            10
        );
        assert_eq!(String::from_utf16(&output[..10]).unwrap(), "node-value");
        assert_eq!(
            native_set_environment_variable_w(name.as_ptr(), std::ptr::null()),
            1
        );
        assert_eq!(
            native_get_environment_variable_w(
                name.as_ptr(),
                output.as_mut_ptr(),
                output.len() as u32
            ),
            0
        );
        assert_eq!(native_get_last_error(), 203);
    }

    #[test]
    fn executable_search_current_directory_policy_matches_windows() {
        let executable: Vec<u16> = "powershell.exe"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let path_executable: Vec<u16> = "tools\\powershell.exe"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let policy_name: Vec<u16> = "NoDefaultCurrentDirectoryInExePath"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let empty_value = [0u16];

        assert_eq!(
            native_set_environment_variable_w(policy_name.as_ptr(), std::ptr::null()),
            1
        );
        assert_eq!(
            native_need_current_directory_for_exe_path_w(executable.as_ptr()),
            1
        );
        assert_eq!(
            native_set_environment_variable_w(policy_name.as_ptr(), empty_value.as_ptr()),
            1
        );
        assert_eq!(
            native_need_current_directory_for_exe_path_w(executable.as_ptr()),
            0
        );
        assert_eq!(
            native_need_current_directory_for_exe_path_w(path_executable.as_ptr()),
            1
        );
        assert_eq!(
            native_need_current_directory_for_exe_path_w(std::ptr::null()),
            0
        );
        assert_eq!(
            native_set_environment_variable_w(policy_name.as_ptr(), std::ptr::null()),
            1
        );
    }

    #[test]
    fn native_child_lookup_resolves_the_power_shell_shell_link_from_path() {
        let mut fs = WinFs::new();
        fs.mkdir(r"C:\work").unwrap();
        fs.mkdir(r"C:\bin").unwrap();
        fs.set_cwd(r"C:\work").unwrap();
        fs.write_file(
            r"C:\bin\powershell.exe",
            crate::shell::POWERSHELL_SHELL_LINK.to_vec(),
        )
        .unwrap();
        let mut launch = NativeLaunchSpec {
            application: fs.normalize("powershell.exe").unwrap().display(),
            arguments: vec![
                "powershell.exe".to_string(),
                "-NoProfile".to_string(),
                "-Command".to_string(),
                "Write-Output shell-link-ok".to_string(),
            ],
            current_directory: fs.cwd(),
        };
        super::native_resolve_launch_application(
            &mut launch,
            &fs,
            &[("PATH".to_string(), r"C:\bin".to_string())],
        );
        assert_eq!(launch.application, r"C:\bin\powershell.exe");
        assert!(crate::shell::is_powershell_shell_link(
            &fs,
            &launch.application
        ));

        let (status, stdout, stderr) =
            super::execute_powershell_shell_link(&mut fs, &launch.arguments[1..]);
        assert_eq!(status, 0);
        assert_eq!(stdout, b"shell-link-ok\n");
        assert!(stderr.is_empty());
    }

    #[test]
    fn supplies_a_root_current_directory() {
        let mut output = [0; 4];
        assert_eq!(native_get_current_directory_w(4, output.as_mut_ptr()), 3);
        assert_eq!(&output, &['C' as u16, ':' as u16, '\\' as u16, 0]);
        assert_eq!(native_get_current_directory_w(3, output.as_mut_ptr()), 4);
    }

    #[test]
    fn supplies_a_synthetic_computer_name() {
        let mut len = 0;
        assert_eq!(
            native_get_computer_name_ex_w(5, std::ptr::null_mut(), &mut len),
            0
        );
        assert_eq!(len, 7);
        let mut output = [0; 7];
        assert_eq!(
            native_get_computer_name_ex_w(5, output.as_mut_ptr(), &mut len),
            1
        );
        assert_eq!(
            &output[..6],
            &['w' as u16, 'i' as u16, 'n' as u16, 'c' as u16, 'l' as u16, 'i' as u16]
        );
    }

    #[test]
    fn supplies_x64_system_information() {
        let mut output = [0; 48];
        native_get_system_info(output.as_mut_ptr());
        assert_eq!(u16::from_le_bytes(output[..2].try_into().unwrap()), 9);
        assert_eq!(u32::from_le_bytes(output[4..8].try_into().unwrap()), 4096);
        assert_eq!(
            u32::from_le_bytes(output[40..44].try_into().unwrap()),
            65_536
        );
    }

    #[test]
    fn supplies_a_nanosecond_performance_frequency() {
        let mut frequency = 0;
        assert_eq!(native_query_performance_frequency(&mut frequency), 1);
        assert_eq!(frequency, 1_000_000_000);
    }

    #[test]
    fn wait_on_address_reports_changed_values_and_timeouts() {
        let value = 0u8;
        let expected = 1u8;
        assert_eq!(
            native_wait_on_address(
                (&value as *const u8).cast(),
                (&expected as *const u8).cast(),
                1,
                u32::MAX
            ),
            1
        );
        assert_eq!(
            native_wait_on_address(std::ptr::null(), (&expected as *const u8).cast(), 1, 0),
            0
        );
        assert_eq!(native_get_last_error(), 87);
        let unchanged = 0u8;
        assert_eq!(
            native_wait_on_address(
                (&value as *const u8).cast(),
                (&unchanged as *const u8).cast(),
                1,
                0
            ),
            0
        );
        assert_eq!(native_get_last_error(), 1460);
    }

    #[test]
    fn wait_on_address_parks_until_the_guest_value_changes_and_wakes() {
        let value = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let address = std::sync::Arc::as_ptr(&value) as usize;
        let value_for_thread = std::sync::Arc::clone(&value);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let expected = 0u32;
            started_tx.send(()).unwrap();
            let result = native_wait_on_address(
                std::sync::Arc::as_ptr(&value_for_thread).cast(),
                (&expected as *const u32).cast(),
                4,
                1000,
            );
            result_tx.send(result).unwrap();
        });
        started_rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        value.store(1, std::sync::atomic::Ordering::Release);
        native_wake_by_address_all(address as *const u8);
        assert_eq!(
            result_rx.recv_timeout(std::time::Duration::from_secs(1)),
            Ok(1)
        );
        worker.join().unwrap();
    }

    #[test]
    fn creates_an_immediately_signaled_waitable_timer() {
        let timer = native_create_waitable_timer_ex_w(std::ptr::null(), std::ptr::null(), 0, 0);
        assert_ne!(timer, 0);
        assert_eq!(
            native_set_waitable_timer(timer, std::ptr::null(), 0, 0, 0, 0),
            1
        );
    }

    #[test]
    fn expands_relative_paths_from_the_native_root() {
        let input = ['.' as u16, 0];
        let mut output = [0; 4];
        assert_eq!(
            native_get_full_path_name_w(
                input.as_ptr(),
                4,
                output.as_mut_ptr(),
                std::ptr::null_mut()
            ),
            3
        );
        assert_eq!(&output, &['C' as u16, ':' as u16, '\\' as u16, 0]);
    }

    #[test]
    fn classifies_native_file_metadata_attributes() {
        assert_eq!(native_file_attributes(true), 0x10);
        assert_eq!(native_file_attributes(false), 0x80);
        assert_eq!(
            super::native_get_file_attributes_w(std::ptr::null()),
            u32::MAX
        );
        assert_eq!(super::native_get_last_error(), 87);
    }

    #[test]
    fn get_file_attributes_ex_reports_winfs_file_and_directory_metadata() {
        let context = super::fs_ctx().unwrap();
        let file_path = r"C:\attribute_ex_unit.txt";
        let directory_path = r"C:\attribute_ex_unit_dir";
        {
            let mut fs = context.lock().unwrap();
            fs.fs.write_file(file_path, b"vite".to_vec()).unwrap();
            fs.fs.mkdir(directory_path).unwrap();
        }
        let file_path_wide = file_path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let directory_path_wide = directory_path.encode_utf16().chain([0]).collect::<Vec<_>>();
        let mut data = [0u32; 9];
        assert_eq!(
            super::native_get_file_attributes_ex_w(
                file_path_wide.as_ptr(),
                0,
                data.as_mut_ptr().cast(),
            ),
            1
        );
        assert_eq!(data[0], 0x80);
        assert_eq!(data[7], 0);
        assert_eq!(data[8], 4);
        assert_eq!(
            super::native_set_file_attributes_w(file_path_wide.as_ptr(), 0x22),
            1
        );
        assert_eq!(
            super::native_get_file_attributes_w(file_path_wide.as_ptr()),
            0x22
        );
        assert_eq!(
            super::native_set_file_attributes_w(file_path_wide.as_ptr(), 0x80 | 0x2),
            0
        );
        assert_eq!(
            super::native_get_file_attributes_ex_w(
                directory_path_wide.as_ptr(),
                0,
                data.as_mut_ptr().cast(),
            ),
            1
        );
        assert_eq!(data[0], 0x10);
        assert_eq!((data[7], data[8]), (0, 0));
        assert_eq!(
            super::native_get_file_attributes_ex_w(
                file_path_wide.as_ptr(),
                1,
                data.as_mut_ptr().cast(),
            ),
            0
        );
        assert_eq!(super::native_get_last_error(), 87);

        let missing_path = r"C:\missing_attribute_ex_unit.txt"
            .encode_utf16()
            .chain([0])
            .collect::<Vec<_>>();
        assert_eq!(
            super::native_get_file_attributes_ex_w(
                missing_path.as_ptr(),
                0,
                data.as_mut_ptr().cast(),
            ),
            0
        );
        assert_eq!(super::native_get_last_error(), 2);
        let mut fs = context.lock().unwrap();
        fs.fs.delete_file(file_path).unwrap();
        fs.fs.rmdir(directory_path).unwrap();
    }

    #[test]
    fn nt_file_metadata_reports_winfs_size_type_and_id() {
        let process = super::process_ctx().unwrap();
        let handle = {
            let mut fs = process.fs.lock().unwrap();
            let handle = fs.next;
            fs.next += 1;
            let path = format!(r"C:\nt_metadata_{handle}.txt");
            fs.fs.write_file(&path, b"metadata".to_vec()).unwrap();
            fs.handles.insert(
                handle,
                super::NativeFile {
                    path,
                    offset: 0,
                    overlapped: false,
                    completion: None,
                },
            );
            handle
        };
        let mut io_status = [0u8; 16];
        let mut device = [0u8; 8];
        assert_eq!(
            super::native_nt_query_volume_information_file(
                handle,
                io_status.as_mut_ptr(),
                device.as_mut_ptr(),
                device.len() as u32,
                4,
            ),
            0
        );
        assert_eq!(u32::from_le_bytes(device[..4].try_into().unwrap()), 7);
        assert_eq!(u64::from_le_bytes(io_status[8..16].try_into().unwrap()), 8);
        let mut info = [0u8; 104];
        assert_eq!(
            super::native_nt_query_information_file(
                handle,
                io_status.as_mut_ptr(),
                info.as_mut_ptr(),
                info.len() as u32,
                18,
            ),
            0
        );
        assert_eq!(u32::from_le_bytes(info[32..36].try_into().unwrap()), 0x80);
        assert_eq!(u64::from_le_bytes(info[48..56].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(info[56..60].try_into().unwrap()), 1);
        assert_ne!(u64::from_le_bytes(info[64..72].try_into().unwrap()), 0);
        assert_eq!(
            u64::from_le_bytes(io_status[8..16].try_into().unwrap()),
            104
        );
        assert_eq!(&info[96..104], &[0; 8]);
        assert_eq!(
            super::native_nt_query_information_file(
                handle,
                io_status.as_mut_ptr(),
                info.as_mut_ptr(),
                8,
                18,
            ),
            0xC000_0004
        );
        assert_eq!(
            super::native_nt_query_volume_information_file(
                handle + 1000,
                io_status.as_mut_ptr(),
                device.as_mut_ptr(),
                device.len() as u32,
                4,
            ),
            0xC000_0008
        );
        assert_eq!(
            super::native_nt_query_information_file(
                handle,
                io_status.as_mut_ptr(),
                info.as_mut_ptr(),
                info.len() as u32,
                7,
            ),
            0xC000_0002
        );
        let mut fs = process.fs.lock().unwrap();
        let path = fs.handles.remove(&handle).unwrap().path;
        fs.fs.delete_file(&path).unwrap();
    }

    #[test]
    fn encodes_extended_final_paths() {
        assert_eq!(native_extended_path("C:\\"), "\\\\?\\C:\\");
    }

    #[test]
    fn supplies_a_synthetic_user_profile_directory() {
        let mut len = 0;
        assert_eq!(
            native_get_user_profile_directory_w(u64::MAX - 3, std::ptr::null_mut(), &mut len),
            0
        );
        assert_eq!(len, 20);
        let mut output = [0; 32];
        assert_eq!(
            native_get_user_profile_directory_w(u64::MAX - 3, output.as_mut_ptr(), &mut len),
            1
        );
        assert_eq!(
            String::from_utf16_lossy(&output[..19]),
            "C:\\Users\\Win-Runner"
        );
    }

    #[test]
    fn supplies_a_standard_console_screen_buffer() {
        let mut output = [0; 22];
        assert_eq!(
            native_get_console_screen_buffer_info(1, output.as_mut_ptr()),
            1
        );
        assert_eq!(i16::from_le_bytes(output[..2].try_into().unwrap()), 80);
        assert_eq!(i16::from_le_bytes(output[2..4].try_into().unwrap()), 25);
    }

    #[test]
    fn supplies_standard_console_cursor_information() {
        let mut output = [0u8; 8];
        assert_eq!(native_get_console_cursor_info(1, output.as_mut_ptr()), 1);
        assert_eq!(u32::from_le_bytes(output[..4].try_into().unwrap()), 25);
        assert_eq!(i32::from_le_bytes(output[4..].try_into().unwrap()), 1);
        assert_eq!(native_get_console_cursor_info(99, output.as_mut_ptr()), 0);
    }

    #[test]
    fn validates_console_cursor_shape_without_resizing_host_terminal() {
        let mut information = [0u8; 8];
        information[..4].copy_from_slice(&25u32.to_le_bytes());
        information[4..].copy_from_slice(&0i32.to_le_bytes());
        assert_eq!(native_set_console_cursor_info(1, information.as_ptr()), 1);
        information[..4].copy_from_slice(&101u32.to_le_bytes());
        assert_eq!(native_set_console_cursor_info(1, information.as_ptr()), 0);
        assert_eq!(native_set_console_cursor_info(99, information.as_ptr()), 0);
    }

    #[test]
    fn validates_cursor_positions_for_terminal_dimensions() {
        assert_eq!(native_set_console_cursor_position(1, 79 | (24 << 16)), 1);
        assert_eq!(native_set_console_cursor_position(1, 80), 0);
        assert_eq!(native_set_console_cursor_position(99, 0), 0);
    }

    #[test]
    fn console_output_cell_api_is_bound_and_rejects_invalid_geometry() {
        let cell = [b' '; 4];
        let mut region = [0i16, 0, 0, 0];
        assert!(super::baseline_trampoline("WriteConsoleOutputA").is_some());
        assert_eq!(
            super::native_write_console_output_a(
                1,
                cell.as_ptr(),
                0,
                0,
                region.as_mut_ptr().cast(),
            ),
            0
        );
    }

    #[test]
    fn accepts_console_mode_changes_for_standard_handles() {
        assert_eq!(native_set_console_mode(1, 5), 1);
        assert_eq!(native_set_console_mode(99, 5), 0);
    }

    #[test]
    fn accepts_valid_console_screen_buffer_sizes_for_standard_handles() {
        let coord = u32::from(80u16) | (u32::from(25u16) << 16);
        assert_eq!(native_set_console_screen_buffer_size(1, coord), 1);
        assert_eq!(native_set_console_screen_buffer_size(99, coord), 0);
        assert_eq!(native_set_console_screen_buffer_size(1, 0), 0);
    }

    #[test]
    fn validates_console_window_rectangles_without_resizing_the_host() {
        let valid = [0i16, 0, 79, 24];
        let invalid = [4i16, 0, 3, 24];
        assert_eq!(
            native_set_console_window_info(1, 1, valid.as_ptr().cast()),
            1
        );
        assert_eq!(
            native_set_console_window_info(1, 1, invalid.as_ptr().cast()),
            0
        );
        assert_eq!(
            native_set_console_window_info(99, 1, valid.as_ptr().cast()),
            0
        );
    }

    #[test]
    fn accepts_standard_console_as_active_screen_buffer() {
        assert_eq!(native_set_console_active_screen_buffer(1), 1);
        assert_eq!(native_set_console_active_screen_buffer(99), 0);
    }

    #[test]
    fn formats_a_native_system_error_message() {
        let mut output = [0; 32];
        let count = native_format_message_w(0, 0, 5, 0, output.as_mut_ptr(), 32, 0);
        assert_eq!(
            String::from_utf16_lossy(&output[..count as usize]),
            "Win-Runner native error.\r\n"
        );
    }

    #[test]
    fn formats_ansi_system_error_and_rejects_short_buffer() {
        let mut short = [0u8; 4];
        assert_eq!(
            native_format_message_a(0x1000, 0, 5, 0, short.as_mut_ptr(), 4, 0),
            0
        );
        let mut output = [0u8; 64];
        let count = native_format_message_a(0x1000, 0, 5, 0, output.as_mut_ptr(), 64, 0);
        assert_eq!(&output[..count as usize], b"Win-Runner native error.\r\n");
        assert_eq!(output[count as usize], 0);
    }

    #[test]
    fn exposes_the_main_module_handle() {
        assert_eq!(
            native_get_module_handle_w(std::ptr::null()),
            0x0001_4000_0000
        );
    }

    #[test]
    fn exposes_the_main_module_through_module_handle_ex() {
        let mut handle = 0;
        assert_eq!(
            native_get_module_handle_ex_w(0, std::ptr::null(), &mut handle),
            1
        );
        assert_eq!(handle, 0x0001_4000_0000);
    }

    #[test]
    fn resolves_supported_dynamic_api_set_exports() {
        assert_ne!(
            native_get_proc_address(API_SET_MODULE, c"CompareStringEx".as_ptr().cast()),
            0
        );
        assert_eq!(
            native_get_proc_address(API_SET_MODULE, c"GetEnvironmentVariableW".as_ptr().cast()),
            native_get_environment_variable_w as *const () as usize as u64
        );
        assert_ne!(
            native_get_proc_address(API_SET_MODULE, c"FlsAlloc".as_ptr().cast()),
            0
        );
        assert_eq!(
            native_get_proc_address(API_SET_MODULE, c"UnknownExport".as_ptr().cast()),
            0
        );
    }

    #[test]
    fn folds_ascii_case_without_changing_non_ascii_utf16() {
        let mut value = ['a' as u16, 'Z' as u16, 0x00e9];
        uppercase_ascii_utf16(&mut value);
        assert_eq!(value, ['A' as u16, 'Z' as u16, 0x00e9]);
    }

    #[test]
    fn single_threaded_critical_sections_initialize_and_are_callable() {
        let mut section = [0xa5; 40];
        assert_eq!(
            native_initialize_critical_section_ex(section.as_mut_ptr(), 0, 0),
            1
        );
        assert_eq!(section, [0; 40]);
        native_enter_critical_section(section.as_mut_ptr());
        native_leave_critical_section(section.as_mut_ptr());
        native_delete_critical_section(section.as_mut_ptr());
    }

    #[test]
    fn critical_section_serializes_threads_and_allows_recursion() {
        let mut section = [0u8; 40];
        let section_ptr = section.as_mut_ptr();
        assert_eq!(native_initialize_critical_section_ex(section_ptr, 0, 0), 1);
        native_enter_critical_section(section_ptr);
        native_enter_critical_section(section_ptr);
        native_leave_critical_section(section_ptr);

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let section_address = section_ptr as usize;
        let worker = std::thread::spawn(move || {
            THREAD_NATIVE_HANDLE.with(|handle| handle.set(0xface));
            started_tx.send(()).unwrap();
            native_enter_critical_section(section_address as *mut u8);
            entered_tx.send(()).unwrap();
            native_leave_critical_section(section_address as *mut u8);
        });

        started_rx.recv().unwrap();
        assert!(entered_rx
            .recv_timeout(std::time::Duration::from_millis(20))
            .is_err());
        native_leave_critical_section(section_ptr);
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        worker.join().unwrap();
        native_delete_critical_section(section_ptr);
    }

    #[test]
    fn initializes_an_empty_64_bit_slist_header() {
        let mut header = [0xa5; 16];
        native_initialize_slist_head(header.as_mut_ptr());
        assert_eq!(header, [0; 16]);
    }

    #[test]
    fn ioctlsocket_and_connect_validate_handles_and_arguments() {
        let socket = 0x534f_434b_0000_0003;
        let mut argument = 1u32;
        assert_eq!(
            native_ioctlsocket(3, 0x8004_667e_u32 as i32, &mut argument),
            -1
        );
        assert_eq!(native_wsa_get_last_error(), 10038);
        assert_eq!(native_ioctlsocket(socket, 0x1234, &mut argument), -1);
        assert_eq!(native_wsa_get_last_error(), 10022);
        assert_eq!(
            native_ioctlsocket(socket, 0x8004_667e_u32 as i32, std::ptr::null_mut()),
            -1
        );
        assert_eq!(native_wsa_get_last_error(), 10014);
        assert_eq!(native_connect_socket(socket, std::ptr::null(), 16), -1);
        assert_eq!(native_wsa_get_last_error(), 10014);
        assert_eq!(native_listen_socket(3, 128), -1);
        assert_eq!(native_wsa_get_last_error(), 10038);
        assert_eq!(native_shutdown_socket(3, 2), -1);
        assert_eq!(native_wsa_get_last_error(), 10038);
    }

    #[test]
    fn inet_addr_uses_its_correct_ws2_32_ordinal() {
        assert_eq!(
            native_wsa_inet_addr(c"127.0.0.1".as_ptr().cast()),
            u32::from_ne_bytes([127, 0, 0, 1])
        );
        assert_eq!(native_wsa_inet_addr(c"invalid".as_ptr().cast()), u32::MAX);
    }

    #[test]
    fn pushes_pops_and_flushes_native_slist_entries() {
        #[repr(align(16))]
        struct Aligned([u64; 2]);
        let mut header = Aligned([0; 2]);
        let mut first = Aligned([0; 2]);
        let mut second = Aligned([0; 2]);
        let head = header.0.as_mut_ptr().cast::<u8>();
        let first = first.0.as_mut_ptr().cast::<u8>();
        let second = second.0.as_mut_ptr().cast::<u8>();
        native_initialize_slist_head(head);
        assert!(native_interlocked_push_entry_slist(head, first).is_null());
        assert_eq!(native_query_depth_slist(head), 1);
        assert_eq!(native_interlocked_push_entry_slist(head, second), first);
        assert_eq!(native_query_depth_slist(head), 2);
        assert_eq!(native_interlocked_pop_entry_slist(head), second);
        assert_eq!(native_interlocked_pop_entry_slist(head), first);
        assert!(native_interlocked_pop_entry_slist(head).is_null());
        assert_eq!(native_query_depth_slist(head), 0);
        assert!(native_interlocked_push_entry_slist(head, first).is_null());
        assert_eq!(native_interlocked_flush_slist(head), first);
        assert_eq!(native_query_depth_slist(head), 0);
    }

    #[test]
    fn preserves_the_native_child_last_error() {
        native_set_last_error(87);
        assert_eq!(native_get_last_error(), 87);
        native_set_last_error(0);
    }

    #[test]
    fn provides_a_zeroed_64_bit_startup_info_record() {
        let mut startup_info = [0xa5; 104];
        native_get_startup_info_w(startup_info.as_mut_ptr());
        assert_eq!(
            u32::from_le_bytes(startup_info[..4].try_into().unwrap()),
            104
        );
        assert!(startup_info[4..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn classifies_native_standard_descriptors_by_terminal_state() {
        for fd in 0..=2 {
            assert_eq!(
                native_get_file_type(fd),
                if unsafe { super::isatty(fd as i32) } != 0 {
                    2
                } else {
                    3
                }
            );
        }
        assert_eq!(native_get_file_type(0x100), 0);
    }

    #[test]
    fn exposes_a_synthetic_windows_module_path() {
        let mut path = [0; 32];
        let len = native_get_module_file_name_w(0, path.as_mut_ptr(), path.len() as u32);
        assert_eq!(
            String::from_utf16(&path[..len as usize]).unwrap(),
            "C:\\winrun\\winrun.exe"
        );
        let mut short = [0; 3];
        assert_eq!(native_get_module_file_name_w(0, short.as_mut_ptr(), 3), 3);
        assert_eq!(short, ['C' as u16, ':' as u16, '\\' as u16]);
    }

    #[test]
    fn resolves_loaded_windows_module_names_in_wide_form() {
        let kernel: Vec<u16> = "KERNEL32.dll"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        assert_eq!(native_get_module_handle_w(kernel.as_ptr()), API_SET_MODULE);
        let missing: Vec<u16> = "missing.dll"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        assert_eq!(native_get_module_handle_w(missing.as_ptr()), 0);
    }

    #[test]
    fn exposes_and_frees_a_child_local_empty_environment_block() {
        let block = native_get_environment_strings_w();
        assert_eq!(unsafe { std::slice::from_raw_parts(block, 2) }, &[0, 0]);
        assert_eq!(native_free_environment_strings_w(block), 1);
        assert_eq!(native_free_environment_strings_w(std::ptr::null()), 0);
    }

    #[test]
    fn stores_the_child_unhandled_exception_filter() {
        assert_eq!(native_set_unhandled_exception_filter(0x1234), 0);
        assert_eq!(native_set_unhandled_exception_filter(0), 0x1234);
    }

    #[test]
    fn registers_multiple_vectored_exception_handlers_with_opaque_handles() {
        assert_eq!(native_add_vectored_exception_handler(1, 0), 0);
        assert_eq!(native_add_vectored_exception_handler(0, 0), 0);
        let first = native_add_vectored_exception_handler(1, 0x1234);
        let second = native_add_vectored_exception_handler(2, 0x5678);
        assert_ne!(first, 0);
        assert_ne!(second, 0);
        assert_ne!(first, second);
        assert_eq!(native_remove_vectored_exception_handler(first), 1);
        assert_eq!(native_remove_vectored_exception_handler(first), 0);
        assert_eq!(native_remove_vectored_exception_handler(second), 1);
    }

    static RAISED_EXCEPTION_CODE: std::sync::atomic::AtomicU32 =
        std::sync::atomic::AtomicU32::new(0);

    extern "win64" fn handle_raised_exception(
        pointers: *mut super::NativeExceptionPointers,
    ) -> i32 {
        let record = unsafe { &*(*pointers).record };
        RAISED_EXCEPTION_CODE.store(record.code, std::sync::atomic::Ordering::Release);
        -1 // EXCEPTION_CONTINUE_EXECUTION
    }

    #[test]
    fn dispatches_raise_exception_to_a_vectored_handler() {
        RAISED_EXCEPTION_CODE.store(0, std::sync::atomic::Ordering::Release);
        let handle = native_add_vectored_exception_handler(
            1,
            handle_raised_exception as *const () as usize as u64,
        );
        assert_ne!(handle, 0);
        native_raise_exception(0xe123_4567, 0, 0, std::ptr::null());
        assert_eq!(
            RAISED_EXCEPTION_CODE.load(std::sync::atomic::Ordering::Acquire),
            0xe123_4567
        );
        assert_eq!(native_remove_vectored_exception_handler(handle), 1);
    }

    #[test]
    fn rtl_lookup_function_entry_finds_mapped_pe_unwind_ranges() {
        use crate::native::linux_x86_64::state::NativeLoadedModule;

        let mut image = vec![0u8; 0x2000];
        let base = image.as_mut_ptr() as u64;
        let write16 = |offset: usize, value: u16, image: &mut [u8]| {
            image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        };
        let write32 = |offset: usize, value: u32, image: &mut [u8]| {
            image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        };
        write16(0, 0x5a4d, &mut image);
        write32(0x3c, 0x80, &mut image);
        write32(0x80, 0x0000_4550, &mut image);
        write16(0x80 + 20, 0xf0, &mut image);
        write16(0x98, 0x20b, &mut image);
        write32(0x98 + 108, 16, &mut image);
        let exception_directory = 0x98 + 112 + 3 * 8;
        write32(exception_directory, 0x500, &mut image);
        write32(exception_directory + 4, 12, &mut image);
        write32(0x500, 0x1000, &mut image);
        write32(0x504, 0x1200, &mut image);
        write32(0x508, 0x600, &mut image);

        let process = super::process_ctx().unwrap();
        process.loaded_modules.lock().unwrap().insert(
            base,
            NativeLoadedModule {
                path: "C:\\unwind-test.exe".to_string(),
                name: "unwind-test.exe".to_string(),
                base,
                size_of_image: image.len() as u32,
                exports: Vec::new(),
                entry_point: None,
                tls_callbacks: Vec::new(),
                static_tls_index: None,
                static_tls_template: None,
                load_order: 0,
                load_references: 0,
                dependencies: Vec::new(),
                mapping: None,
                initialized: true,
            },
        );

        let mut reported_base = u64::MAX;
        let function = native_rtl_lookup_function_entry(
            base + 0x1100,
            &mut reported_base,
            std::ptr::null_mut(),
        );
        assert_eq!(function, base + 0x500);
        assert_eq!(reported_base, base);

        reported_base = u64::MAX;
        assert_eq!(
            native_rtl_lookup_function_entry(
                base + 0x1300,
                &mut reported_base,
                std::ptr::null_mut()
            ),
            0
        );
        assert_eq!(reported_base, 0);
        process.loaded_modules.lock().unwrap().remove(&base);
    }

    #[test]
    fn dynamic_function_tables_register_lookup_and_remove() {
        let mut functions = [
            super::NativeRuntimeFunction {
                begin_address: 0x100,
                end_address: 0x180,
                unwind_data: 0x400,
            },
            super::NativeRuntimeFunction {
                begin_address: 0x200,
                end_address: 0x280,
                unwind_data: 0x420,
            },
        ];
        let table = functions.as_mut_ptr();
        let base = 0x0000_7fff_1000_0000;
        assert_eq!(native_rtl_add_function_table(table, 2, base), 1);
        assert_eq!(native_rtl_add_function_table(table, 2, base), 0);

        let mut reported_base = 0;
        assert_eq!(
            native_rtl_lookup_function_entry(
                base + 0x240,
                &mut reported_base,
                std::ptr::null_mut()
            ),
            table as u64 + std::mem::size_of::<super::NativeRuntimeFunction>() as u64
        );
        assert_eq!(reported_base, base);
        assert_eq!(native_rtl_delete_function_table(table), 1);
        assert_eq!(native_rtl_delete_function_table(table), 0);
        reported_base = u64::MAX;
        assert_eq!(
            native_rtl_lookup_function_entry(
                base + 0x240,
                &mut reported_base,
                std::ptr::null_mut()
            ),
            0
        );
        assert_eq!(reported_base, 0);

        functions.swap(0, 1);
        assert_eq!(native_rtl_add_function_table(table, 2, base), 0);
    }

    #[test]
    fn accepts_a_thread_stack_guarantee_request() {
        let mut size = 0x5000;
        assert_eq!(native_set_thread_stack_guarantee(&mut size), 1);
        assert_eq!(native_set_thread_stack_guarantee(std::ptr::null_mut()), 0);
    }

    #[test]
    fn converts_command_lines_to_a_null_terminated_ansi_view() {
        assert_eq!(command_line_a(&['r' as u16, 'g' as u16, 0]), b"rg\0");
        assert_eq!(command_line_a(&[0x00e9, 0]), b"?\0");
    }

    #[test]
    fn reports_a_consistent_single_byte_windows_code_page() {
        assert_eq!(native_get_acp(), 1252);
        assert_eq!(native_get_oem_cp(), 1252);
    }

    #[test]
    fn validates_only_implemented_code_pages() {
        assert_eq!(native_is_valid_code_page(1252), 1);
        assert_eq!(native_is_valid_code_page(65001), 1);
        assert_eq!(native_is_valid_code_page(0), 1);
        assert_eq!(native_is_valid_code_page(1), 1);
        assert_eq!(native_is_valid_code_page(3), 1);
        assert_eq!(native_is_valid_code_page(932), 0);
        assert_eq!(native_resolve_code_page(0), native_get_acp());
        assert_eq!(native_resolve_code_page(1), native_get_oem_cp());
        assert_eq!(native_resolve_code_page(3), native_get_acp());
    }

    #[test]
    fn converts_using_the_acp_and_oem_code_page_aliases() {
        let input = [0xe9];
        let mut wide = [0u16; 1];
        for code_page in [0, 1, 3] {
            assert_eq!(
                native_multi_byte_to_wide_char(
                    code_page,
                    0,
                    input.as_ptr(),
                    input.len() as i32,
                    wide.as_mut_ptr(),
                    wide.len() as i32,
                ),
                1
            );
            assert_eq!(wide, [0xe9]);
        }
        let mut byte = [0];
        assert_eq!(
            native_wide_char_to_multi_byte(
                1,
                0,
                wide.as_ptr(),
                1,
                byte.as_mut_ptr(),
                1,
                std::ptr::null(),
                std::ptr::null_mut(),
            ),
            1
        );
        assert_eq!(byte, input);
        let euro = [0x80, 0];
        let mut euro_wide = [0u16; 2];
        assert_eq!(
            native_multi_byte_to_wide_char(0, 0, euro.as_ptr(), -1, euro_wide.as_mut_ptr(), 2),
            2
        );
        assert_eq!(euro_wide, [0x20ac, 0]);
    }

    #[test]
    fn fills_code_page_info_for_supported_pages() {
        let mut cp_info = [0xa5; 16];
        assert_eq!(native_get_cp_info(1252, cp_info.as_mut_ptr()), 1);
        assert_eq!(u32::from_le_bytes(cp_info[..4].try_into().unwrap()), 1);
        assert_eq!(cp_info[4], b'?');
        assert!(cp_info[5..].iter().all(|byte| *byte == 0));
        assert_eq!(native_get_cp_info(65001, cp_info.as_mut_ptr()), 1);
        assert_eq!(u32::from_le_bytes(cp_info[..4].try_into().unwrap()), 4);
        assert_eq!(native_get_cp_info(932, cp_info.as_mut_ptr()), 0);
    }

    #[test]
    fn converts_supported_multibyte_inputs_to_utf16() {
        let input = b"rg\0";
        let mut output = [0; 4];
        assert_eq!(
            native_multi_byte_to_wide_char(1252, 0, input.as_ptr(), -1, output.as_mut_ptr(), 4),
            3
        );
        assert_eq!(&output[..3], &['r' as u16, 'g' as u16, 0]);
        assert_eq!(
            native_multi_byte_to_wide_char(65001, 0, "é".as_ptr(), 2, std::ptr::null_mut(), 0),
            1
        );
        assert_eq!(
            native_multi_byte_to_wide_char(932, 0, input.as_ptr(), -1, output.as_mut_ptr(), 4),
            0
        );
    }

    #[test]
    fn classifies_ascii_characters_for_the_crt() {
        let input = ['A' as u16, '7' as u16, ' ' as u16, '!' as u16];
        let mut output = [0; 4];
        assert_eq!(
            native_get_string_type_w(1, input.as_ptr(), 4, output.as_mut_ptr()),
            1
        );
        assert_eq!(output, [0x0101, 0x0084, 0x0048, 0x0010]);
        assert_eq!(
            native_get_string_type_w(2, input.as_ptr(), 4, output.as_mut_ptr()),
            0
        );
    }

    #[test]
    fn maps_ascii_case_and_reports_wide_output_size() {
        let input = ['R' as u16, 'g' as u16, 0];
        let mut output = [0; 3];
        assert_eq!(
            native_lc_map_string_w(
                std::ptr::null(),
                0x100,
                input.as_ptr(),
                -1,
                output.as_mut_ptr(),
                3
            ),
            3
        );
        assert_eq!(output, ['r' as u16, 'g' as u16, 0]);
        assert_eq!(
            native_lc_map_string_w(
                std::ptr::null(),
                0,
                input.as_ptr(),
                -1,
                std::ptr::null_mut(),
                0
            ),
            3
        );
    }

    #[test]
    fn converts_wide_input_to_supported_multibyte_pages() {
        let input = ['r' as u16, 'g' as u16, 0];
        let mut output = [0; 3];
        assert_eq!(
            native_wide_char_to_multi_byte(
                1252,
                0,
                input.as_ptr(),
                -1,
                output.as_mut_ptr(),
                3,
                std::ptr::null(),
                std::ptr::null_mut()
            ),
            3
        );
        assert_eq!(output, *b"rg\0");
        let euro = [0x20ac, 0];
        let mut euro_bytes = [0u8; 2];
        assert_eq!(
            native_wide_char_to_multi_byte(
                0,
                0,
                euro.as_ptr(),
                -1,
                euro_bytes.as_mut_ptr(),
                2,
                std::ptr::null(),
                std::ptr::null_mut()
            ),
            2
        );
        assert_eq!(euro_bytes, [0x80, 0]);
        assert_eq!(
            native_wide_char_to_multi_byte(
                65001,
                0,
                ['é' as u16].as_ptr(),
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
                std::ptr::null_mut()
            ),
            2
        );
    }
}
