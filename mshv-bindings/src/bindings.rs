include!("./bindings-generated.rs");

impl Default for hv_message_header {
    #[inline]
    fn default() -> Self {
        let mut uninit = std::mem::MaybeUninit::<Self>::uninit();
        let ptr = uninit.as_mut_ptr();

        // SAFETY: We know that the pointer generated from uninit is not NULL. We use
        // write_unaligned because the struct is packed.
        unsafe {
            std::ptr::addr_of_mut!((*ptr).message_type).write_unaligned(hv_message_type_HVMSG_NONE);
        }

        // SAFETY: An hv_message_header with the message type being NONE is valid.
        unsafe { uninit.assume_init() }
    }
}

impl Default for hv_message {
    #[inline]
    fn default() -> Self {
        let mut uninit = std::mem::MaybeUninit::<Self>::uninit();
        let ptr = uninit.as_mut_ptr();

        // SAFETY: We know that the pointer generated from uninit is not NULL. We use
        // write_unaligned because the struct is packed.
        unsafe {
            std::ptr::addr_of_mut!((*ptr).header).write_unaligned(hv_message_header::default());
        }

        // SAFETY: An hv_message with the default header is valid. See
        // hv_message_header::default(). The message type is NONE, hence its users
        // are not allowed to read from or write to other fields.
        unsafe { uninit.assume_init() }
    }
}

#[test]
fn test_hv_message_header_default() {
    let h = hv_message_header::default();
    let t = h.message_type;
    assert_eq!(t, hv_message_type_HVMSG_NONE);
}

#[test]
fn test_hv_message_default() {
    let m = hv_message::default();
    let t = m.header.message_type;
    assert_eq!(t, hv_message_type_HVMSG_NONE);
}
