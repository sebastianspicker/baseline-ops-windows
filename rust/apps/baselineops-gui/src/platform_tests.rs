use super::callback::CallbackState;

#[test]
fn synchronous_reentry_cannot_alias_mutable_app_access() {
    let state = CallbackState::new(0_u8);
    assert!(state.enter());

    assert_eq!(
        state.with_app(|app| {
            *app = 1;
            assert!(state.enter());
            assert!(state.with_app(|nested| *nested = 2).is_none());
            assert!(!state.leave());
        }),
        Some(())
    );

    assert!(!state.leave());
    assert_eq!(state.callback_depth.get(), 0);
    assert_eq!(*state.app.borrow(), 1);
}

#[test]
fn destruction_during_nested_dispatch_defers_release_to_outer_callback() {
    let state = CallbackState::new(());
    assert!(state.enter());
    assert!(state.enter());

    assert!(state.begin_destroy());
    assert!(!state.begin_destroy());
    assert!(state.with_app(|()| ()).is_none());
    assert!(!state.leave());
    assert!(state.leave());
}
