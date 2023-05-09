<?php
/**
 * Plugin Name: Simple IP Blocker
 * Plugin URI: https://github.com/dc4e/simple-ip-blocker
 * Description: A small plugin for creating IP blocklists. IPs can be blocked via REMOTE_ADDR or if the application runs behind a proxy via X-Forwarded-For. The plugin adds a subpage to the main menu of the settings page.
 * Author: maybebernd
 * Version: 1.0.1
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

    if (
        isset( $_SERVER["HTTP_X_FORWARDED_FOR"] ) &&
        false !== filter_var( $_SERVER["HTTP_X_FORWARDED_FOR"] , FILTER_VALIDATE_IP ) &&
        ip_check( $_SERVER["HTTP_X_FORWARDED_FOR"], 'sib_blocked_xff_ips' )      
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
        ip_check( $_SERVER["REMOTE_ADDR"], 'sib_blocked_ra_ips' )
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
 * Checks if the client ip is inside the blocklist or part of a block list CIDR
 * 
 * @since 1.0.0
 * 
 * @param string $client_ip
 * @param string $block_list
 * @return bool
 */
function ip_check( string $client_ip, string $block_list_name ) {
    
    if ( empty( $block_list_name ) ) {
        return false;
    }
    
    $block_list = \get_option( $block_list_name, [] );

    $in_block_list = false;
    foreach( $block_list as $entry ) {

        if ( 
            false !== strpos( $entry, '/' ) &&
            ip_cidr_check( $client_ip, $entry )
        ) {
            $in_block_list = true;
            break;
        } elseif ( $client_ip === $entry ) {
            $in_block_list = true;
            break;
        }

    }

    return $in_block_list;

}

/**
 * Checks if the client ip is part of a blocked cidr
 * 
 * @since 1.0.0
 * 
 * @see https://www.php.net/manual/en/ref.network.php#74656
 * 
 * @param string $client_ip
 * @param string $cidr
 * @return true
 */
function ip_cidr_check( $client_ip, $cidr ) {
    
    list ($net, $mask) = explode("/", $cidr);

    $ip_net = ip2long($net);
    $ip_mask = ~((1 << (32 - $mask)) - 1);
    
    $ip_ip = ip2long ($client_ip);

    $ip_ip_net = $ip_ip & $ip_mask;

    return ($ip_ip_net == $ip_net);

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

    \register_setting(
        'sib-options',
        'sib_blocked_htaccess_xff_ips',
        [
            'type' => 'array',
            'description' => __( 'comma-separated list of blocked htaccess X-Forwarded-For IPs', 'simple-ip-blocker' ),
            'sanitize_callback' => __NAMESPACE__ . '\sanitize_xff_for_htaccess_ip_list',
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

    if ( is_string( $ip_list ) ) {
        $ips = explode( ',', $ip_list );
    } else {
        $ips = $ip_list;
    }

    $sanitized_ips = [];

    foreach( $ips as $ip ) {

        $ip = trim( $ip );

        if ( false !== strpos( $ip, '/' ) ) {
            $range_parts = explode( '/', $ip );

            $ip = $range_parts[0];
            $cidr = (int) $range_parts[1];

            if (
                false === filter_var( $ip, FILTER_VALIDATE_IP ) ||
                0 > $cidr ||
                32 < $cidr
            ) {
                continue;
            }

            $ip = "{$ip}/{$cidr}";


        } elseif ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            continue;
        }

        $sanitized_ips[] = $ip;

    }

    $sanitized_ips = array_unique( $sanitized_ips );

    return $sanitized_ips;

}

function sanitize_xff_for_htaccess_ip_list( $ip_list ) {

    $sanitized_ips = sanitize_ip_list( $ip_list );

    if ( empty( $sanitized_ips ) ) {
        return [];
    }

    update_htaccess_file( $sanitized_ips );

    return $sanitized_ips;

}

function update_htaccess_file( $ip_list ) {

    if ( empty( $ip_list ) ) {
        return;
    }

    $htaccess_file = ABSPATH . '/.htaccess';

    if ( ! file_exists( $htaccess_file ) ) {
        touch( $htaccess_file );
    }

    $htaccess_content = file_get_contents( $htaccess_file );

    $start_string = "\n\n# BEGIN Simple-IP-Blocker Rules\n";
    $end_string = "# END Simple-IP-Blocker Rules\n";

    $rule_template = get_htaccess_content_template();

    $current_rule_start_index = strpos( $htaccess_content, $start_string );

    if ( false === $current_rule_start_index ) {
        // Adds the rule
        $htaccess_content .= sprintf(
            $rule_template, implode( '","', $ip_list )
        );
    } else {

        $current_rule_length = strpos( $htaccess_content, $end_string, $current_rule_start_index ) + strlen( $end_string ) - $current_rule_start_index;

        $current_rule = substr( $htaccess_content, $current_rule_start_index, $current_rule_length );

        $blocked_ips = '';

        foreach( $ip_list as $ip ) {

            if ( false !== strpos( $ip, '/' ) ) {
                $ip_parts = explode( '.', $ip );
                $ip = "{$ip_parts[0]}.{$ip_parts[1]}.{$ip_parts[2]}.";
            }

            $ip = str_replace( '.', '\.', $ip );

            $blocked_ips .=  "\tSetEnvIF X-FORWARDED-FOR \"^{$ip}\" DenyIP\n";
        }

        $htaccess_content = str_replace( 
            $current_rule,
            sprintf(
                $rule_template, $blocked_ips
            ),
            $htaccess_content 
        );

    }

    file_put_contents( $htaccess_file, $htaccess_content );

}

function get_htaccess_content_template() {

    return "\n\n# BEGIN Simple-IP-Blocker Rules\n\n<Files *>\n%s\tOrder allow,deny\n\tAllow from all\n\tDeny from env=DenyIP\n</Files>\n\n# END Simple-IP-Blocker Rules\n";

}


/**
 * Displays the settings page html
 * 
 * @since 1.0.0
 */
function display_options_page() {
    
    $blocked_xff_ips = \get_option( 'sib_blocked_xff_ips', [] );
    $blocked_ra_ips = \get_option( 'sib_blocked_ra_ips', [] );
    $blocked_htaccess_xff_ips = \get_option( 'sib_blocked_htaccess_xff_ips', [] );

    $blocked_xff_ips = implode( ', ', $blocked_xff_ips );
    $blocked_ra_ips = implode( ', ', $blocked_ra_ips );
    $blocked_htaccess_xff_ips = implode( ', ', $blocked_htaccess_xff_ips );

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

            <h5>
                <?php esc_html_e( 'Blocking over \'plugin_loaded\' hook' );?>
            </h5>
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

            <h5>
                <?php esc_html_e( 'Blocking XFF via the .htaccess file. (experimental)' );?>
            </h5>
           
            <div style="display: flex; flex-direction: column; margin-right: 20px;">
                <label for="sib_blocked_htaccess_xff_ips">
                    <?php \esc_html_e( 'Enter a comma-separated list of X-Forwarded-For IPs to block.', 'simple-ip-blocker' );?>
                </label>
                <textarea id="sib_blocked_htaccess_xff_ips" name="sib_blocked_htaccess_xff_ips"><?php echo \esc_html( $blocked_htaccess_xff_ips );?></textarea>
            </div>
        
            <?php \submit_button(); ?>

        </form>

    </div>
    <?php

}
