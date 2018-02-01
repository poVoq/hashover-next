<?php namespace HashOver;

// Copyright (C) 2010-2016 Jacob Barkdull
// This file is part of HashOver.
//
// HashOver is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// HashOver is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with HashOver.  If not, see <http://www.gnu.org/licenses/>.


// Display source code
if (basename ($_SERVER['PHP_SELF']) === basename (__FILE__)) {
	if (isset ($_GET['source'])) {
		header ('Content-type: text/plain; charset=UTF-8');
		exit (file_get_contents (basename (__FILE__)));
	} else {
		exit ('<b>HashOver</b>: This is a class file.');
	}
}

// Encryption methods
class Encryption
{
    protected $prefix;
    protected $cost = '$10$';
    protected $cipher = 'aes-256-gcm';
    protected $iv;
    protected $encryption_key;

    public function __construct () {
	$this->prefix = (version_compare (PHP_VERSION, '5.3.7') < 0) ? '$2a' : '$2y';
        $this->encryption_key = base64_encode(openssl_random_pseudo_bytes(32));
        $this->iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->cipher));
    }

	// Creates Blowfish hash for passwords
	public function createHash ($str)
	{
		// Generate alphameric array
		$alphabet = str_split ('aAbBcCdDeEfFgGhHiIjJkKlLmM.nNoOpPqQrRsStTuUvVwWxXyYzZ/0123456789');
		shuffle ($alphabet);
		$salt = '';

		// Generate random 20 character alphameric string
		foreach (array_rand ($alphabet, 20) as $alphameric) {
			$salt .= $alphabet[$alphameric];
		}

		// Return hashed string
		return crypt ($str, $this->prefix . $this->cost . $salt . '$$');
	}

	// Creates Blowfish hash with salt from supplied hash; returns true if both match
	public function verifyHash ($str, $compare)
	{
		$salt = explode ('$', $compare);
		$hash = crypt ($str, $this->prefix . $this->cost . $salt[3] . '$$');

		return ($hash === $compare) ? true : false;
	}

// encrypt  string
 public function encrypt ($str) {

   // Remove the base64 encoding from our key
    $encrypt_key = base64_decode($this->encryption_key);

    // Encrypt the data using AES 256 encryption in gcm mode using our encryption key and initialization vector.
    $encrypted = openssl_encrypt($str, $this->cipher, $encrypt_key, $options=0, $this->iv, $tag);

        // Return encrypted value and list of encryption hash array keys
        return array (
            'encrypted' => base64_encode ($encrypted),
            'keys' => $this->cipher . ',' . $this->encryption_key . ',' . base64_encode($this->iv) . ',' . base64_encode($tag)
        );
    }

// Decrypt openssl_encrypt string
public function decrypt ($str, $encrypted_keys) {

if (!empty ($str) && !empty ($encrypted_keys)) {

    $decrypted = base64_decode($str, true);

   list($cipher, $encrypt_key, $iv, $tag) = explode(',', $encrypted_keys);

        $encrypt_key = base64_decode($encrypt_key);
        $iv = base64_decode($iv);
        $tag = base64_decode($tag);

     if ($decrypted !== false and !empty ($decrypted)) {

         $decrypted = openssl_decrypt($decrypted, $cipher, $encrypt_key, $options=0, $iv, $tag);

         return $decrypted;

            }
        }
        return false;
    }
}
