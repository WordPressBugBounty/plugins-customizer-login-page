<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly
}
/** Section : Presets  */
		$wp_customize->add_section(
			'lpc-section-presets',
			array(
				'title' => __( 'Presets', 'customizer-login-page' ),
				'panel' => 'lpc-main-panel',
			)
		);
			// Presets heading control.
			$wp_customize->add_setting(
				'lpc-presets-heading',
				array(
					'default'           => '',
					'sanitize_callback' => 'sanitize_text_field',
				)
			);
			$wp_customize->add_control(
				new Lpc_Simple_Notice_Custom_control(
					$wp_customize,
					'lpc-presets-heading-control',
					array(
						'label'    => __( 'Predefined Templates', 'customizer-login-page' ),
						'settings' => 'lpc-presets-heading',
						'section'  => 'lpc-section-presets',
					)
				)
			);
			// Preset Grid Control.
			$lpc_presets_choices = array(
				'default'    => array(
					'image' => LOGINPC_PLUGIN_URL . 'assets/presets/images/default_thumb.jpg',
					'name'  => __('Default', 'customizer-login-page'),
				),
				'gradient'   => array(
					'image' => LOGINPC_PLUGIN_URL . 'assets/presets/images/gradient_thumb.jpg',
					'name'  => __('Gradient', 'customizer-login-page'),
				),
				'chirp'      => array(
					'image' => LOGINPC_PLUGIN_URL . 'assets/presets/images/chirp_thumb.jpg',
					'name'  => __('Chirp', 'customizer-login-page'),
				),
				'education'  => array(
					'image' => LOGINPC_PLUGIN_URL . 'assets/presets/images/education_thumb.jpg',
					'name'  => __('Education', 'customizer-login-page'),
				),
				'circle'     => array(
					'image' => LOGINPC_PLUGIN_URL . 'assets/presets/images/circle_thumb.jpg',
					'name'  => __('Circle', 'customizer-login-page'),
				),
				'portal'     => array(
					'image' => LOGINPC_PLUGIN_URL . 'assets/presets/images/portal_thumb.jpg',
					'name'  => __('Portal', 'customizer-login-page'),
				),
				'colorful'   => array(
					'image' => LOGINPC_PLUGIN_URL . 'assets/presets/images/colorful_thumb.jpg',
					'name'  => __('Colorful', 'customizer-login-page'),
				),
				'crystal'    => array(
					'image' => LOGINPC_PLUGIN_URL . 'assets/presets/images/crystal_thumb.jpg',
					'name'  => __('Crystal', 'customizer-login-page'),
				),
				'secure'     => array(
					'image' => LOGINPC_PLUGIN_URL . 'assets/presets/images/secure_thumb.jpg',
					'name'  => __('Secure', 'customizer-login-page'),
				),
				'invite'     => array(
					'image' => LOGINPC_PLUGIN_URL . 'assets/presets/images/invite_thumb.jpg',
					'name'  => __('Invite', 'customizer-login-page'),
				),
				'crypto'     => array(
					'image' => LOGINPC_PLUGIN_URL . 'assets/presets/images/crypto_thumb.jpg',
					'name'  => __('Crypto', 'customizer-login-page'),
				),
				'darkaqua'   => array(
					'image' => LOGINPC_PLUGIN_URL . 'assets/presets/images/darkaqua_thumb.jpg',
					'name'  => __('Darkaqua', 'customizer-login-page'),
				),
				'celebrate'  => array(
					'image' => LOGINPC_PLUGIN_URL . 'assets/presets/images/celebrate_thumb.jpg',
					'name'  => __('Celebrate', 'customizer-login-page'),
				),
				'anime'      => array(
					'image' => LOGINPC_PLUGIN_URL . 'assets/presets/images/anime_thumb.jpg',
					'name'  => __('Anime', 'customizer-login-page'),
				),
				'medical'    => array(
					'image' => LOGINPC_PLUGIN_URL . 'assets/presets/images/medical_thumb.jpg',
					'name'  => __('Medical', 'customizer-login-page'),
				),
				'lock'       => array(
					'image' => LOGINPC_PLUGIN_URL . 'assets/presets/images/lock_thumb.jpg',
					'name'  => __('Lock', 'customizer-login-page'),
				),
				'gaming'     => array(
					'image' => LOGINPC_PLUGIN_URL . 'assets/presets/images/gaming_thumb.jpg',
					'name'  => __('Gaming', 'customizer-login-page'),
				),
				'naturetech' => array(
					'image' => LOGINPC_PLUGIN_URL . 'assets/presets/images/naturetech_thumb.jpg',
					'name'  => __('Naturetech', 'customizer-login-page'),
				),
				'park' => array(
					'image' => LOGINPC_PLUGIN_URL . 'assets/presets/images/park_thumb.jpg',
					'name'  => __('Park', 'customizer-login-page'),
				),
			);

			// Sort the choices by 'name', keeping 'default' at the top.
			uasort(
				$lpc_presets_choices,
				function( $a, $b ) {
					if ( $a['name'] === __('Default', 'customizer-login-page') ) {
						return -1;
					}
					if ( $b['name'] === __('Default', 'customizer-login-page') ) {
						return 1;
					}
					return strcmp( $a['name'], $b['name'] );
				}
			);

			// Add setting preset.
			$wp_customize->add_setting(
				'lpc_preset_select',
				array(
					'type'              => 'option',
					'transport'         => 'refresh',
					'sanitize_callback' => 'sanitize_text_field',
				)
			);
			$wp_customize->add_control(
				new Lpc_Image_Radio_Button_Custom_Control(
					$wp_customize,
					'lpc_preset_select_control',
					array(
						'label'    => __( 'Select Template', 'customizer-login-page' ),
						'section'  => 'lpc-section-presets',
						'settings' => 'lpc_preset_select',
						'choices'  => $lpc_presets_choices,
					)
				)
			);
