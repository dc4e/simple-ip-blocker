<?php
/**
 * Contains the uninstall routine
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    die;
}

$options_to_delete = [
    'sib_blocked_xff_ips',
    'sib_blocked_ra_ips',
    'sib_blocked_htaccess_xff_ips'
];

foreach( $options_to_delete as $option_key ) {

    delete_option( $option_key );

    // for site options in Multisite
    delete_site_option( $option_key );

}

$htaccess_file = ABSPATH . '/.htaccess';

if ( file_exists( $htaccess_file ) ) {
    
    $htaccess_content = file_get_contents( $htaccess_file );

    $start_string = "\n\n# BEGIN Simple-IP-Blocker Rules\n";
    $end_string = "# END Simple-IP-Blocker Rules\n";

    $current_rule_start_index = strpos( $htaccess_content, $start_string );

    if ( false !== $current_rule_start_index ) {

        $current_rule_length = strpos( $htaccess_content, $end_string, $current_rule_start_index ) + strlen( $end_string ) - $current_rule_start_index;

        $current_rule = substr( $htaccess_content, $current_rule_start_index, $current_rule_length );

        $htaccess_content = str_replace( $current_rule, '', $htaccess_content );

        file_put_contents( $htaccess_file, $htaccess_content );

    }

}