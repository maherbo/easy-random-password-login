<?php
class Crypt{		
	public static function encrypt($data, $password, $options = OPENSSL_RAW_DATA){
	//	Set $options to '0' to get a base64 encoded encryption

		// Pad $data to a block of 16 bytes (encode the padded length with the selected padding character ASCII code)
		$length = 16 - strlen($data) % 16;
		$paddedData = $data . str_repeat(chr($length), $length);

		//	Get new IV
		$iv = openssl_random_pseudo_bytes(16);		
		
		//	With openssl_encrypt's options set to 0, you get some non-ASCII, control and/or space characters -> encode it afterward
		$encrypted = openssl_encrypt(
			$paddedData,    // padded data
			'AES-256-CBC',  // cipher and mode
			md5($password), // set 32 bytes length for key
			OPENSSL_RAW_DATA,
			$iv
		);

		//	Return $iv AND encrypted data:
		if($options === 0){
			return base64_encode($iv.$encrypted);
		}
		else{
			return $iv.$encrypted;
		}		
	}

	public static function decrypt($encryptedData, $password, $options = OPENSSL_RAW_DATA){
	//	Set $options to '0' to decrypt a base64 encoded encryption
	//	Returns boolean 'false' on failure (wrong password)		
		
		//	See comment in function encrypt() for base64 encoding
		if($options == 0){
			$encryptedData = base64_decode($encryptedData);
		}
		$decrypted = openssl_decrypt(
			substr($encryptedData, 16),   // first 16 bytes is IV
			'AES-256-CBC',                // cipher and mode
			md5($password),               // set 32 bytes length for key
			OPENSSL_RAW_DATA,
			substr($encryptedData, 0, 16) // retrieve IV from encrypted data
		);
		
		//	Un-pad (see function 'encrypt')
		if($decrypted){
			$decrypted = substr($decrypted, 0, -ord($decrypted[strlen($decrypted) - 1]));
		}

		return $decrypted;
	}

	public static function password_verify($password, $hashed_password, $options = ['cost' => 10]){
	//	Returns false on failure;
	//	If the password and hash match, it returns true or a new hashed password, if rehashing is needed.
	
		if(function_exists("password_verify")){
			if(password_verify($password, $hashed_password)){
				if(password_needs_rehash($hashed_password, PASSWORD_DEFAULT, $options)){
					return self::password_hash($password, $options);
				}
				else return true;
			}
			else return false;
		}
		else{	//	PHP < 5.5.0
			return (crypt($password, $hashed_password) == $hashed_password);
		}
	}

	public static function password_hash($password, $options = ['cost' => 10]){
		if(function_exists("password_hash")){
			return password_hash($password, PASSWORD_DEFAULT, $options);
		}
		else{	//	PHP < 5.5.0
			$salt = mcrypt_create_iv(21, MCRYPT_DEV_URANDOM);	/*get random string*/
			$salt = base64_encode($salt);	/*convert to base64*/
			$salt = substr($salt,0,21);	/*keep the first 21 characters only*/
			$salt = preg_replace("/\+/",".",$salt);	/*replace the '+'s by '.'s (base64_encode uses the alphabet [A-Za-z0-9+/] and Blowfish hash accept the alphabet [A-Za-z0-9./])*/

			return crypt($password,'$2y$'.$options['cost'].'$'.$salt);
		}
	}

	public static function getHashedPasswordKeyCode($userPassword){
		$password = md5(mcrypt_create_iv(32, MCRYPT_DEV_RANDOM)).md5(mcrypt_create_iv(32, MCRYPT_DEV_RANDOM));
		
		$array['key'] = md5(mcrypt_create_iv(32, MCRYPT_DEV_RANDOM)).md5(mcrypt_create_iv(32, MCRYPT_DEV_RANDOM));
		
		$array['hashed_password'] = self::password_hash($password);
		
		$array['code'] = self::encrypt($password, $userPassword.$array['key'], 0);
		
		return $array;
	}

	public static function getPasswordFrom($code, $userPassword, $key){
		$password = self::decrypt($code, $userPassword.$key, 0);

		return $password;
	}
}