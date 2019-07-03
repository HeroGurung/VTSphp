<?php
$response = array();
include 'db_connect.php';
$random_salt_length = 32;

// Get the _POST request parameters
$inputJSON = file_get_contents('php://input');
$input = json_decode($inputJSON, TRUE); //convert JSON into array

// echo $_POSTJSON;
function getSalt()
{
	// echo "salt function";
	global $random_salt_length;
	return bin2hex(openssl_random_pseudo_bytes($random_salt_length));
}

//Creates password salt used to append to hashing for not making hash for same password
function concatPasswordWithSalt($password,$salt)
{
	global $random_salt_length;
	if($random_salt_length % 2 == 0){
		$mid = $random_salt_length / 2;
	}
	else{
		$mid = ($random_salt_length - 1) / 2;
	}
 
	return
	substr($salt,0,$mid - 1).$password.substr($salt,$mid,$random_salt_length - 1);
}
 
// Check for Mandatory parameters
if(isset($_POST['username']) && isset($_POST['password']) && isset($_POST['full_name']))
{
$username = $_POST['username'];
$password = $_POST['password'];
$full_name = $_POST['full_name'];
	
//Create function to search username in database
function userExists($username)
{
	$query = "SELECT username FROM userdb WHERE username = ?";
	global $con;
	if($stmt = $con->prepare($query))
	{
		$stmt->bind_param("s",$username);
		$stmt->execute();
		$stmt->store_result();
		$stmt->fetch();
		if($stmt->num_rows == 1)
		{
			$stmt->close();
			return true;
		}
		$stmt->close();
	}
	return false;
}

// checks username exists or not
	if(!userExists($username))
	{
		//Get a unique Salt
		$salt = getSalt();

		//Generate a unique password Hash
		 $passwordHash = password_hash(concatPasswordWithSalt($password,$salt),PASSWORD_DEFAULT);
		
		//Query to register new user
		$insertQuery  = "INSERT INTO userdb(username, full_name, password_hash, salt) VALUES (?,?,?,?)";
		if($stmt = $con->prepare($insertQuery))
		{
			$stmt->bind_param("ssss",$username,$full_name,$passwordHash,$salt);
			$stmt->execute();
			$response["status"] = 0;
			$response["message"] = "User created";
			$stmt->close();
		}
	}
	else
	{
		$response["status"] = 1;
		$response["message"] = "User exists";
	}
}
else
{
$response["status"] = 2;
$response["message"] = "Miss parameters";
}
echo json_encode($response);
?>