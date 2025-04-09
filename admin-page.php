<?php
function dkim_mail_signer_settings_page() {
    $options = get_option(DKIM_SIGNER_OPTION);
    $domain = isset($options['domain']) ? esc_attr($options['domain']) : '';
    $test_email = '';
    $message = '';
    $public_key_output = '';
    $private_key_path = plugin_dir_path(__FILE__) . 'private.key';

    // テストメール送信処理
    if (isset($_POST['send_test_email']) && check_admin_referer('dkim_mail_signer_send_test')) {
        $test_email = sanitize_email($_POST['test_email']);
        if (is_email($test_email)) {
            $subject = 'テストメール from DKIM Mail Signer';
            $body = 'これはDKIM署名テストメールです。';
            $headers = ['Content-Type: text/plain; charset=UTF-8'];
            if (wp_mail($test_email, $subject, $body, $headers)) {
                $message = '<div class="updated"><p>テストメールを送信しました！</p></div>';
            } else {
                $message = '<div class="error"><p>テストメールの送信に失敗しました。</p></div>';
            }
        } else {
            $message = '<div class="error"><p>有効なメールアドレスを入力してください。</p></div>';
        }
    }

    // 秘密鍵生成処理
    if (isset($_POST['generate_key']) && check_admin_referer('dkim_mail_signer_generate_key')) {
        if (!extension_loaded('openssl')) {
            $message = '<div class="error"><p>OpenSSLがPHPに有効化されていません。</p></div>';
        } else {
            $key_res = openssl_pkey_new([
                'private_key_bits' => 2048,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ]);
            openssl_pkey_export($key_res, $private_key);
            $pub_key_details = openssl_pkey_get_details($key_res);
            $public_key_raw = $pub_key_details['key'];

            // 保存
            file_put_contents($private_key_path, $private_key);
            chmod($private_key_path, 0600);

            // 公開鍵をDNS形式で整形
            $public_key_clean = preg_replace('/\-{5}(BEGIN|END) PUBLIC KEY\-{5}|\s+/', '', $public_key_raw);
            $selector = 'default';
            $domain_display = $domain ?: 'example.com';
            $public_key_output = <<<HTML
<div class="updated"><p><strong>秘密鍵を生成しました。</strong></p>
<p>以下の内容をDNSに追加してください：</p>
<code>{$selector}._domainkey.{$domain_display} IN TXT "v=DKIM1; k=rsa; p={$public_key_clean}"</code>
</div>
HTML;
        }
    }

    // 秘密鍵削除処理
    if (isset($_POST['delete_key']) && check_admin_referer('dkim_mail_signer_delete_key')) {
        if (file_exists($private_key_path)) {
            unlink($private_key_path);
            $message = '<div class="updated"><p>秘密鍵を削除しました。</p></div>';
        } else {
            $message = '<div class="error"><p>秘密鍵は存在しません。</p></div>';
        }
    }

    if (isset($_POST['verify_key']) && check_admin_referer('dkim_mail_signer_verify_key')) {
        if (!file_exists($private_key_path)) {
            $message = '<div class="error"><p>秘密鍵ファイルが存在しません。</p></div>';
        } else {
            $private_key = file_get_contents($private_key_path);
            $key_res = openssl_pkey_get_private($private_key);
            if (!$key_res) {
                $message = '<div class="error"><p>秘密鍵の読み込みに失敗しました。</p></div>';
            } else {
                $details = openssl_pkey_get_details($key_res);
                $public_key_raw = $details['key'];
                $public_key_clean = preg_replace('/\-{5}(BEGIN|END) PUBLIC KEY\-{5}|\s+/', '', $public_key_raw);
                $selector = 'default';
                $domain_display = $domain ?: 'example.com';
                $dns_domain = "{$selector}._domainkey.{$domain_display}";
    
                // DNSからTXTレコード取得
                $dns_records = dns_get_record($dns_domain, DNS_TXT);
                $dns_found = false;
                $dns_p_value = '';
    
                foreach ($dns_records as $record) {
                    if (isset($record['txt'])) {
                        if (preg_match('/p=([a-zA-Z0-9+\/=]+)/', $record['txt'], $matches)) {
                            $dns_found = true;
                            $dns_p_value = trim($matches[1]);
                            break;
                        }
                    }
                }
    
                // 比較
                if ($dns_found) {
                    if ($dns_p_value === $public_key_clean) {
                        $public_key_output = <<<HTML
<div class="updated"><p><strong>鍵ペアは有効で、DNSに登録された公開鍵と一致しています。</strong></p></div>
HTML;
                    } else {
                        $public_key_output = <<<HTML
<div class="error"><p><strong>公開鍵がDNSに登録されている内容と一致しません。</strong></p>
<p>期待値（秘密鍵に対応）：<br><code>{$public_key_clean}</code></p>
<p>DNSの値：<br><code>{$dns_p_value}</code></p>
</div>
HTML;
                    }
                } else {
                    $public_key_output = <<<HTML
<div class="error"><p>DNSにTXTレコードが見つかりませんでした：<code>{$dns_domain}</code></p></div>
HTML;
                }
            }
        }
    }
    

    // UI出力
    echo '<div class="wrap">';
    echo '<h1>DKIM Mail Signer 設定</h1>';
    echo $message;
    echo $public_key_output;

    echo '<form method="post" action="options.php">';
    settings_fields(DKIM_SIGNER_OPTION);
    do_settings_sections(DKIM_SIGNER_OPTION);
    echo '<table class="form-table">';
    echo '<tr><th scope="row"><label for="domain">DKIMドメイン名</label></th>';
    echo '<td><input type="text" name="' . DKIM_SIGNER_OPTION . '[domain]" value="' . $domain . '" class="regular-text" /></td></tr>';
    echo '</table>';
    submit_button();
    echo '</form>';

    // 秘密鍵の存在確認
    $key_exists = file_exists($private_key_path);

    // 鍵生成・削除ボタン
    echo '<hr><h2>秘密鍵の管理</h2>';
    if ($key_exists) {
        echo '<p><strong>秘密鍵は既に存在します。</strong></p>';
        echo '<form method="post">';
        wp_nonce_field('dkim_mail_signer_delete_key');
        submit_button('秘密鍵を削除する', 'delete', 'delete_key');
        echo '</form>';
    } else {
        echo '<form method="post">';
        wp_nonce_field('dkim_mail_signer_generate_key');
        submit_button('秘密鍵を生成する', 'secondary', 'generate_key');
        echo '</form>';
    }

    // 鍵ペアの検証
    echo '<hr><h2>鍵ペアの検証（DNS比較あり）</h2>';
    echo '<form method="post">';
    wp_nonce_field('dkim_mail_signer_verify_key');
    submit_button('鍵ペアを検証する', 'secondary', 'verify_key');
    echo '</form>';

    // テストメール送信
    echo '<hr><h2>テストメール送信</h2>';
    echo '<form method="post">';
    wp_nonce_field('dkim_mail_signer_send_test');
    echo '<table class="form-table">';
    echo '<tr><th scope="row"><label for="test_email">送信先メールアドレス</label></th>';
    echo '<td><input type="email" name="test_email" class="regular-text" required /></td></tr>';
    echo '</table>';
    submit_button('テストメールを送信する', 'primary', 'send_test_email');
    echo '</form>';

    echo '</div>';
}
