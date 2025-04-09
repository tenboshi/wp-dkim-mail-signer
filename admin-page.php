<?php

function dkim_mail_signer_settings_page() {
    $options = get_option(DKIM_SIGNER_OPTION);
    $domain = isset($options['domain']) ? esc_attr($options['domain']) : '';
    $private_key_path = plugin_dir_path(__FILE__) . 'private.key';
    $message = '';
    $public_key_output = '';

    // 処理の実行
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (isset($_POST['send_test_email'])) {
            $message = handle_test_email();
        } elseif (isset($_POST['generate_key'])) {
            $message = handle_generate_key($private_key_path, $domain, $public_key_output);
        } elseif (isset($_POST['delete_key'])) {
            $message = handle_delete_key($private_key_path);
        } elseif (isset($_POST['verify_key'])) {
            $message = handle_verify_key($private_key_path, $domain, $public_key_output);
        }
    }

    // UI出力
    echo '<div class="wrap">';
    echo '<h1>DKIM Mail Signer 設定</h1>';
    echo $message;
    echo $public_key_output;

    render_settings_form($domain);
    render_key_management_section($private_key_path);
    render_test_email_section();
    echo '</div>';
}

function handle_test_email() {
    if (!check_admin_referer('dkim_mail_signer_send_test')) {
        return '';
    }

    $test_email = sanitize_email($_POST['test_email']);
    if (!is_email($test_email)) {
        return render_message('有効なメールアドレスを入力してください。', 'error');
    }

    $subject = 'テストメール from DKIM Mail Signer';
    $body = 'これはDKIM署名テストメールです。';
    $headers = ['Content-Type: text/plain; charset=UTF-8'];

    if (wp_mail($test_email, $subject, $body, $headers)) {
        return render_message('テストメールを送信しました！', 'updated');
    } else {
        return render_message('テストメールの送信に失敗しました。', 'error');
    }
}

function handle_generate_key($private_key_path, $domain, &$public_key_output) {
    if (!check_admin_referer('dkim_mail_signer_generate_key')) {
        return '';
    }

    if (!extension_loaded('openssl')) {
        return render_message('OpenSSLがPHPに有効化されていません。', 'error');
    }

    $key_res = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);
    openssl_pkey_export($key_res, $private_key);
    $pub_key_details = openssl_pkey_get_details($key_res);
    $public_key_raw = $pub_key_details['key'];

    file_put_contents($private_key_path, $private_key);
    chmod($private_key_path, 0600);

    $public_key_clean = preg_replace('/\-{5}(BEGIN|END) PUBLIC KEY\-{5}|\s+/', '', $public_key_raw);
    $selector = 'default';
    $domain_display = $domain ?: 'example.com';

    $public_key_output = <<<HTML
<div class="updated"><p>以下の内容をDNSに追加してください：</p>
<code style="display: inline-block; white-space: pre-wrap; word-wrap: break-word; width: 100%;">{$selector}._domainkey.{$domain_display} IN TXT "v=DKIM1; k=rsa; p={$public_key_clean}"</code>
</div>
HTML;

    return render_message('秘密鍵を生成しました。', 'updated');
}

function handle_delete_key($private_key_path) {
    if (!check_admin_referer('dkim_mail_signer_delete_key')) {
        return '';
    }

    if (file_exists($private_key_path)) {
        unlink($private_key_path);
        return render_message('秘密鍵を削除しました。', 'updated');
    } else {
        return render_message('秘密鍵は存在しません。', 'error');
    }
}

function handle_verify_key($private_key_path, $domain, &$public_key_output) {
    if (!check_admin_referer('dkim_mail_signer_verify_key')) {
        return '';
    }

    if (!file_exists($private_key_path)) {
        return render_message('秘密鍵ファイルが存在しません。', 'error');
    }

    $private_key = file_get_contents($private_key_path);
    $key_res = openssl_pkey_get_private($private_key);
    if (!$key_res) {
        return render_message('秘密鍵の読み込みに失敗しました。', 'error');
    }

    $details = openssl_pkey_get_details($key_res);
    $public_key_raw = $details['key'];
    $public_key_clean = preg_replace('/\-{5}(BEGIN|END) PUBLIC KEY\-{5}|\s+/', '', $public_key_raw);
    $selector = 'default';
    $domain_display = $domain ?: 'example.com';
    $dns_domain = "{$selector}._domainkey.{$domain_display}";

    $dns_records = dns_get_record($dns_domain, DNS_TXT);
    foreach ($dns_records as $record) {
        if (isset($record['txt']) && preg_match('/p=([a-zA-Z0-9+\/=]+)/', $record['txt'], $matches)) {
            $dns_p_value = trim($matches[1]);
            if ($dns_p_value === $public_key_clean) {
                return render_message('鍵ペアは有効で、DNSに登録された公開鍵と一致しています。', 'updated');
            } else {
                return render_message('公開鍵がDNSに登録されている内容と一致しません。', 'error');
            }
        }
    }

    return render_message("DNSにTXTレコードが見つかりませんでした：<code>{$dns_domain}</code>", 'error');
}

function render_settings_form($domain) {
    echo '<form method="post" action="options.php">';
    settings_fields(DKIM_SIGNER_OPTION);
    do_settings_sections(DKIM_SIGNER_OPTION);
    echo '<table class="form-table">';
    echo '<tr><th scope="row"><label for="domain">DKIMドメイン名</label></th>';
    echo '<td><input type="text" name="' . DKIM_SIGNER_OPTION . '[domain]" value="' . $domain . '" class="regular-text" /></td></tr>';
    echo '</table>';
    submit_button();
    echo '</form>';
}

function render_key_management_section($private_key_path) {
    $key_exists = file_exists($private_key_path);
    echo '<hr><h2>秘密鍵の管理</h2>';
    if ($key_exists) {
        echo '<p><strong>秘密鍵は既に存在します。</strong></p>';
        echo '<form method="post">';
        wp_nonce_field('dkim_mail_signer_delete_key');
        submit_button('秘密鍵を削除する', 'delete', 'delete_key');
        echo '</form>';

        // 鍵ペアの検証
        echo '<hr><h2>鍵ペアの検証（DNS比較あり）</h2>';
        echo '<form method="post">';
        wp_nonce_field('dkim_mail_signer_verify_key');
        submit_button('鍵ペアを検証する', 'secondary', 'verify_key');
        echo '</form>';
    } else {
        echo '<form method="post">';
        wp_nonce_field('dkim_mail_signer_generate_key');
        submit_button('秘密鍵を生成する', 'secondary', 'generate_key');
        echo '</form>';
    }
}

function render_test_email_section() {
    echo '<hr><h2>テストメール送信</h2>';
    echo '<form method="post">';
    wp_nonce_field('dkim_mail_signer_send_test');
    echo '<table class="form-table">';
    echo '<tr><th scope="row"><label for="test_email">送信先メールアドレス</label></th>';
    echo '<td><input type="email" name="test_email" class="regular-text" required /></td></tr>';
    echo '</table>';
    submit_button('テストメールを送信する', 'primary', 'send_test_email');
    echo '</form>';
}

function render_message($message, $type) {
    return "<div class=\"{$type}\"><p>{$message}</p></div>";
}
