<?php
/**
 * Secure handler for advance build.
 *
 * Accepts POST only, requires a valid WP nonce and manage_options capability.
 * Recommended usage: call via admin pages or AJAX from an authenticated admin session.
 */

define( 'WP_USE_THEMES', false );

// Adjust path if plugin folder depth differs
require_once dirname( __FILE__ ) . '/../../wp-load.php';

// 1) Only allow POST
if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
    status_header( 405 ); // Method Not Allowed
    wp_send_json_error( array( 'message' => 'Method Not Allowed' ), 405 );
    exit;
}

// 2) Nonce check (expected name: _wpnonce, action: clp_advance_build)
if ( empty( $_POST['_wpnonce'] ) || ! wp_verify_nonce( wp_unslash( $_POST['_wpnonce'] ), 'clp_advance_build' ) ) {
    status_header( 403 );
    wp_send_json_error( array( 'message' => 'Invalid or missing nonce' ), 403 );
    exit;
}

// 3) Capability check: only admins / site owners should be able to run this
if ( ! function_exists( 'current_user_can' ) || ! current_user_can( 'manage_options' ) ) {
    status_header( 403 );
    wp_send_json_error( array( 'message' => 'Insufficient permissions' ), 403 );
    exit;
}

// 4) Input validation / sanitization
$confirm = isset( $_POST['confirm_advance_build'] ) ? sanitize_text_field( wp_unslash( $_POST['confirm_advance_build'] ) ) : '';

if ( $confirm !== 'true' ) {
    status_header( 400 );
    wp_send_json_error( array( 'message' => 'Bad request: missing or invalid parameter' ), 400 );
    exit;
}

// 5) Perform the option changes safely
try {
    if ( get_option( 'clp_build_package', false ) === false ) {
        add_option( 'clp_build_package', 'newlpc' );
    } else {
        update_option( 'clp_build_package', 'newlpc' );
    }

    // Consider logging / capability audit here if desired
    delete_option( 'customizer_login_page_settings' );

    wp_send_json_success( array( 'message' => 'Advance build completed' ) );
} catch ( Exception $e ) {
    // Do not leak internal errors to attacker — send a generic message
    status_header( 500 );
    wp_send_json_error( array( 'message' => 'Internal server error' ), 500 );
}

exit;
