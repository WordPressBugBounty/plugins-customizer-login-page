<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly
}
/**
 * Plugin Name: Customizer Login Page
 * Description: customizer Login Page For WordPress.
 * Version: 2.1.5
 * Author: A WP Life
 * Author URI: https://awplife.com/
 * License: GPLv2 or later
 * Text Domain: customizer-login-page
 * Domain Path: /languages
 */

// Load the modern login page customizer build directly
require_once plugin_dir_path( __FILE__ ) . 'login-page-customizer/login-page-customizer.php';
