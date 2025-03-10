<?php

class AESCipher {
    private $cipher;
    private $key;
    private $iv;
    
    public function __construct($key, $mode = 'cbc') {
        $this->cipher = 'aes-256-' . strtolower($mode);
        $this->key = hash('sha256', $key, true);
        
        if ($mode !== 'ecb') {
            $this->iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->cipher));
        } else {
            $this->iv = ''; 
        }
    }
    
    public function encrypt($plaintext) {
        $ciphertext = openssl_encrypt($plaintext, $this->cipher, $this->key, OPENSSL_RAW_DATA, $this->iv);
        return base64_encode($this->iv . $ciphertext);
    }
    
    public function decrypt($encryptedText) {
        $data = base64_decode($encryptedText);
        $ivLength = openssl_cipher_iv_length($this->cipher);
        
        if ($this->cipher !== 'aes-256-ecb') {
            $this->iv = substr($data, 0, $ivLength);
            $ciphertext = substr($data, $ivLength);
        } else {
            $ciphertext = $data;
        }
        
        return openssl_decrypt($ciphertext, $this->cipher, $this->key, OPENSSL_RAW_DATA, $this->iv);
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action']; 
    $text = $_POST['text'];
    $key = $_POST['key'];
    $mode = $_POST['mode'];
    $aes = new AESCipher($key, $mode);
    
    if ($action === 'encrypt') {
        $encryptedText = $aes->encrypt($text);
        file_put_contents('encrypted.txt', $encryptedText);
        echo "<div class='alert alert-success text-center'>Encrypted text saved to file!</div>";
    } elseif ($action === 'decrypt') {
        $encryptedText = file_get_contents('encrypted.txt');
        $decryptedText = $aes->decrypt($encryptedText);
        echo "<div class='alert alert-info text-center'>Decrypted Text: " . htmlspecialchars($decryptedText) . "</div>";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>AES Encryption/Decryption</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .container {
            max-width: 600px;
            margin-top: 50px;
            text-align: center;
        }
        .card {
            border-radius: 15px;
            box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);
        }
        .btn {
            width: 100%;
        }
        .logo {
            max-width: 200px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <img src="./images/logo-25-lt-color.png" alt="VIKO Logo" class="logo">
        <h4 class="text-center mb-4">AES Encryption/Decryption System</h4>
        <div class="card p-4">
            <form method="post">
                <div class="mb-3">
                    <label class="form-label">Enter Text:</label>
                    <input type="text" name="text" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">Secret Key:</label>
                    <input type="text" name="key" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">Select Mode:</label>
                    <select name="mode" class="form-select">
                        <option value="ecb">ECB</option>
                        <option value="cbc">CBC</option>
                        <option value="cfb">CFB</option>
                    </select>
                </div>
                <button type="submit" name="action" value="encrypt" class="btn btn-primary mb-2">Encrypt</button>
                <button type="submit" name="action" value="decrypt" class="btn btn-success">Decrypt</button>
            </form>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>