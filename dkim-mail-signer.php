<?php
/**
 * Plugin Name: DKIM Mail Signer
 * Description: WordPress の送信メールに DKIM 署名を追加します（外部SMTP不要）。
 * Version: 1.2
 * Author: tenboshi@gmail.com
 */

define('DKIM_SIGNER_OPTION', 'dkim_mail_signer_settings');

add_action('phpmailer_init', 'dkim_mail_signer_add_dkim');
function dkim_mail_signer_add_dkim($phpmailer) {
    $options = get_option(DKIM_SIGNER_OPTION);
    if (empty($options['domain'])) return;

    $phpmailer->DKIM_domain = $options['domain'];
    $phpmailer->DKIM_selector = 'default';
    $phpmailer->DKIM_private = plugin_dir_path(__FILE__) . 'private.key';
    $phpmailer->DKIM_identity = $phpmailer->From;
}

add_action('admin_menu', function() {
    add_options_page('DKIM Mail Signer', 'DKIM Mail Signer', 'manage_options', 'dkim-mail-signer', 'dkim_mail_signer_settings_page');
});

add_action('admin_init', function() {
    register_setting(DKIM_SIGNER_OPTION, DKIM_SIGNER_OPTION);
});

require_once plugin_dir_path(__FILE__) . 'admin-page.php';
