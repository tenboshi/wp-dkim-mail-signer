# DKIM Mail Signer

DKIM Mail Signerは、WordPressから送信されるメールにDKIM署名を自動的に追加するプラグインです。このプラグインは、メールの送信元のドメインを認証し、スパムフィルターによるフィルタリングを防ぎます。

## 機能

- **DKIM署名**：WordPressのメール送信時にDKIM署名を追加します。
- **秘密鍵の生成**：RSA秘密鍵と公開鍵を生成し、DNSに公開するための公開鍵を表示できます。
- **秘密鍵の管理**：既存の秘密鍵を削除し、新しい鍵を生成することができます。
- **テストメール送信**：設定が正しいかテストするためのメールを送信できます。

## インストール方法

1. このプラグインをダウンロードして、`wp-content/plugins` フォルダにアップロードします。
2. WordPress管理画面から「プラグイン」＞「インストール済みプラグイン」へ移動し、「DKIM Mail Signer」を有効化します。
3. プラグインの設定ページに移動し、`DKIMドメイン名` を設定します。
4. 公開鍵をDNSに追加し、メール送信テストを行ってください。

## 使用方法

### DKIM設定

1. WordPress管理画面から「設定」＞「DKIM Mail Signer」に移動します。
2. `DKIMドメイン名` フィールドに、DKIM署名を追加したいドメインを入力して保存します。
3. 「秘密鍵を生成する」ボタンを押して、RSA秘密鍵と公開鍵を生成します。生成した公開鍵をDNSに追加してください。
4. 設定後、テストメールを送信して正しくDKIM署名されているか確認します。

### 鍵管理

- 秘密鍵(private.key)がすでに存在する場合、管理画面に「秘密鍵を削除する」ボタンが表示されます。
- 秘密鍵が存在しない場合、「秘密鍵を生成する」ボタンが表示されます。

### テストメール送信

1. 「テストメール送信」セクションで、送信先メールアドレスを入力し、テストメールを送信します。
2. メールが送信されると、設定されたDKIM署名が正しく追加されているか確認できます。

## 設定

### DKIMドメイン名

- メールのDKIM署名を追加するドメイン名を入力します。例: `example.com`

## トラブルシューティング

- **秘密鍵が生成できない**：`OpenSSL` がPHPで有効化されていることを確認してください。
- **DNSレコードが反映されない**：DNSの伝播に時間がかかる場合があります。最大で24時間かかることがあります。
- **メールが届かない**：メールサーバーが外部からのDKIM署名を許可しているか確認してください。

## ライセンス

このプラグインはMITライセンスのもとで公開されています。詳細については、[LICENSE.md](LICENSE.md) をご確認ください。

## 貢献

- プラグインの改善提案やバグ修正があれば、プルリクエストを歓迎します。
