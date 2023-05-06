<?php
/**
 * Plugin Name: Simple IP Blocker
 * Plugin URI: https://github.com/dc4e/simple-ip-blocker
 * Description: A small plugin for creating IP blocklists. IPs can be blocked via REMOTE_ADDR or if the application runs behind a proxy via X-Forwarded-For. The plugin adds a subpage to the main menu of the settings page.
 * Author: maybebernd
 * Version: 1.0.0
 * 
 */
namespace SimpleIpBlocker;

defined( 'ABSPATH' ) || die();

\add_action(
    'plugin_loaded',
    __NAMESPACE__ . '\check_for_blocked_ips'
);

/**
 * Checks whether the client IP is included in the block lists
 * 
 * @since 1.0.0
 */
function check_for_blocked_ips() {

    $blocked_xff_ips = \get_option( 'sib_blocked_xff_ips', [] );
    $blocked_ra_ips = \get_option( 'sib_blocked_ra_ips', [] );

    
    if (
        isset( $_SERVER["HTTP_X_FORWARDED_FOR"] ) &&
        false !== filter_var( $_SERVER["HTTP_X_FORWARDED_FOR"] , FILTER_VALIDATE_IP ) &&
        (
            false !== in_array( $_SERVER["HTTP_X_FORWARDED_FOR"], $blocked_xff_ips, true ) ||
            false !== in_array( $_SERVER["HTTP_X_FORWARDED_FOR"], $blocked_ra_ips, true )
        )
    ) {
        wp_die(
            'Forbidden',
            'Forbidden',
            [
                'response' => 403
            ]
        );
    } elseif (
        isset( $_SERVER["REMOTE_ADDR"] ) &&
        false !== filter_var( $_SERVER["REMOTE_ADDR"] , FILTER_VALIDATE_IP ) &&
        false !== in_array( $_SERVER["REMOTE_ADDR"], $blocked_ra_ips, true )
    ) {
         wp_die(
            'Forbidden',
            'Forbidden',
            [
                'response' => 403
            ]
        );
    }
    

}

/**
 * Adds the settings submenu page
 * 
 * @since 1.0.0
 */
function add_settings_sub_page() {

    \add_options_page(
        \__( 'IP Blocker', 'simple-ip-blocker' ),
        \__( 'IP Blocker', 'simple-ip-blocker' ),
        'manage_options',
        'options_ip_blocker',
        __NAMESPACE__ . '\display_options_page'
    );

}

/**
 * Adds the necessary menu and settings hooks.
 * 
 * @since 1.0.0
 */
if ( \is_admin() ) {

    \add_action(
        'admin_menu',
        __NAMESPACE__ . '\add_settings_sub_page'
    );

    \add_action(
        'admin_init',
        __NAMESPACE__ . '\register_sib_settings'
    );

}

/**
 * Registers the settings of the block list
 * 
 * @since 1.0.0
 */
function register_sib_settings() {

    \register_setting(
        'sib-options',
        'sib_blocked_xff_ips',
        [
            'type' => 'array',
            'description' => __( 'comma-separated list of blocked X-Forwarded-For IPs', 'simple-ip-blocker' ),
            'sanitize_callback' => __NAMESPACE__ . '\sanitize_ip_list',
            'show_in_rest' => false,
            'default' => ''
        ]
    );

    \register_setting(
        'sib-options',
        'sib_blocked_ra_ips',
        [
            'type' => 'array',
            'description' => __( 'comma-separated list of blocked Remote-Address IPs', 'simple-ip-blocker' ),
            'sanitize_callback' => __NAMESPACE__ . '\sanitize_ip_list',
            'show_in_rest' => false,
            'default' => ''
        ]
    );

}

/**
 * Sanitizes the transmitted block list ips
 * 
 * @since 1.0.0
 * 
 * @param strig $ip_list
 * @return array
 */
function sanitize_ip_list( $ip_list ) {

    if ( empty( $ip_list ) ) {
        return [];
    }

    $ips = explode( ',', $ip_list );

    $sanitized_ips = [];

    foreach( $ips as $ip ) {

        $ip = trim( $ip );

        if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            continue;
        }

        $sanitized_ips[] = $ip;

    }

    $sanitized_ips = array_unique( $sanitized_ips );

    return $sanitized_ips;

}

/**
 * Displays the settings page html
 * 
 * @since 1.0.0
 */
function display_options_page() {
    
    $blocked_xff_ips = \get_option( 'sib_blocked_xff_ips', [] );
    $blocked_ra_ips = \get_option( 'sib_blocked_ra_ips', [] );

    $blocked_xff_ips = implode( ', ', $blocked_xff_ips );
    $blocked_ra_ips = implode( ', ', $blocked_ra_ips );

    ?>
    <div id="sib-options-page-container">

        <h1>
            <?php \esc_html_e( 'IP-Blocker Settings', 'simple-ip-blocker' ); ?>
        </h1>

        <form action="options.php" method="post">
            <?php
            \settings_fields( 'sib-options' );
            \do_settings_sections( 'sib-options' );
            ?>

            <div style="display: flex; flex-direction: column; margin-right: 20px;">
                <label for="sib_blocked_ra_ips">
                    <?php \esc_html_e( 'Enter a comma-separated list of Remote-Address IPs to block.', 'simple-ip-blocker' );?>
                </label>
                <textarea id="sib_blocked_ra_ips" name="sib_blocked_ra_ips"><?php echo \esc_html( $blocked_ra_ips );?></textarea>
            </div>

            <div style="display: flex; flex-direction: column; margin-right: 20px;">
                <label for="sib_blocked_xff_ips">
                    <?php \esc_html_e( 'Enter a comma-separated list of X-Forwarded-For IPs to block.', 'simple-ip-blocker' );?>
                </label>
                <textarea id="sib_blocked_xff_ips" name="sib_blocked_xff_ips"><?php echo \esc_html( $blocked_xff_ips );?></textarea>
            </div>
        
            <?php \submit_button(); ?>

        </form>

    </div>
    <?php

}
