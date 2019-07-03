<?php
$response = array();
$random_salt_length = 32;
include 'db_connect.php';
 
//Get the _POST request parameters
$inputJSON = file_get_contents('php://input');
$input = json_decode($inputJSON, TRUE); //convert JSON into array
 
//password concatination function
function concatPasswordWithSalt($password,$salt)
{
	global $random_salt_length;
	if($random_salt_length % 2 == 0)
	{
		$mid = $random_salt_length / 2;
	}
	else{
		$mid = ($random_salt_length - 1) / 2;
	}
	return
	substr($salt,0,$mid - 1).$password.substr($salt,$mid,$random_salt_length - 1);
 
}

//Check for Mandatory parameters
if(isset($_POST['username']) && isset($_POST['password']))
{
	$username = $_POST['username'];
	$password = $_POST['password'];
	$query    = "SELECT full_name,password_hash, salt FROM userdb WHERE username = ?";
 
	if($stmt = $con->prepare($query))
	{
		$stmt->bind_param("s",$username);
		$stmt->execute();
		$stmt->bind_result($full_name,$passwordHash,$salt);
		if($stmt->fetch())
		{
			//Validate the password
			if(password_verify(concatPasswordWithSalt($password,$salt),$passwordHash))
			{
				$response["status"] = 0;
				$response["message"] = "Login successful";
				$response["full_name"] = $full_name;
			}
			else
			{
				$response["status"] = 1;
				$response["message"] = "Invalid username or password ";
			}
		}
		else
		{
			$response["status"] = 1;
			$response["message"] = "Invalid username and password combination";
		}
		
		$stmt->close();
	}
}
else
{
	$response["status"] = 2;
	$response["message"] = "Missing mandatory parameters";
}
//Display the JSON response
echo json_encode($response);
?>