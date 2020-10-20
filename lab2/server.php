<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\SMTP;


require 'vendor/autoload.php';

$mail = new PHPMailer;
$mail->isSMTP();

$mail->Host='smtp.gmail.com:587';
$mail->port=587;
$mail->SMTPAuth=true;;
$mail->SMTPSecure='tls';

$mail->Username='labceg4399@gmail.com';
$mail->Password='ceglab4399';
$mail->setFrom('labceg4399@gmail.com');
$mail->isHTML(true);
session_start();

// initializing variables
$username = "";
$email    = "";
$errors = array(); 

// connect to the database
$db = mysqli_connect('localhost', 'root', '', 'lab2','3306');

// REGISTER USER
if (isset($_POST['reg_user'])) {
  // receive all input values from the form
  $username = mysqli_real_escape_string($db, $_POST['username']);
  $email = mysqli_real_escape_string($db, $_POST['email']);
  $password_1 = mysqli_real_escape_string($db, $_POST['password_1']);
  $password_2 = mysqli_real_escape_string($db, $_POST['password_2']);

  // form validation: ensure that the form is correctly filled ...
  // by adding (array_push()) corresponding error unto $errors array
  if (empty($username)) { array_push($errors, "Username is required"); }
  if (empty($email)) { array_push($errors, "Email is required"); }
  if (empty($password_1)) { array_push($errors, "Password is required"); }
  if ($password_1 != $password_2) {
	array_push($errors, "The two passwords do not match");
  }

  $epassword = rand(100000,999999);//generating varification password

  // first check the database to make sure 
  // a user does not already exist with the same username and/or email
  $user_check_query = "SELECT * FROM users WHERE username='$username' OR email='$email' LIMIT 1";
  $result = mysqli_query($db, $user_check_query);
  $user = mysqli_fetch_assoc($result);
  
  if ($user) { // if user exists
    if ($user['username'] === $username) {
      array_push($errors, "Username already exists");
    }

    if ($user['email'] === $email) {
      array_push($errors, "email already exists");
      echo '<script language="javascript">';
        echo 'alert("alert test")';
        echo '</script>';
    }
  }

  // Finally, register user if there are no errors in the form
  if (count($errors) == 0) {
  	$password = md5($password_1);//encrypt the password before saving in the database

  	$query = "INSERT INTO users (username, email, password, epassword) 
  			  VALUES('$username', '$email', '$password', '$epassword')";
  	mysqli_query($db, $query);
  	$_SESSION['username'] = $username;
  	$_SESSION['success'] = "You are now logged in";
  	header('location: index.php');
  }
}
//Verify User
//Temporary password check
if (isset($_POST['verify_user'])) {
  $epassword = mysqli_real_escape_string($db, $_POST['epassword']);
  $username = mysqli_real_escape_string($db, $_POST['username']);

  if (empty($epassword)) {
    array_push($errors, "Password is required");
  }

  if (count($errors) == 0) {
      
    $query2 = "SELECT * FROM users WHERE username='$username' AND epassword='$epassword'";
    $results2 = mysqli_query($db, $query2);
    if (mysqli_num_rows($results2) == 1) {
      $_SESSION['username'] = $username;
      $_SESSION['success'] = "You are now logged in";
      header('location: index.php');
    }else {
      array_push($errors, "Wrong password");
    }
  }
}

// LOGIN USER
//First password check
if (isset($_POST['login_user'])) {
  $username = mysqli_real_escape_string($db, $_POST['username']);
  $password = mysqli_real_escape_string($db, $_POST['password']);

  if (empty($username)) {
    array_push($errors, "Username is required");
  }
  if (empty($password)) {
  	array_push($errors, "Password is required");
  }

  if (count($errors) == 0) {
  
  	$password = md5($password);
    //$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
    $query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
    $results = mysqli_query($db, $query);
  	if (mysqli_num_rows($results) == 1) {

      //second password check
      $epassword = rand(100000,999999); //generating varification password
      mysqli_query($db,"UPDATE users SET epassword = $epassword WHERE username = '$username'");
      //email structure
      //$mail->addAddress("srure008@uottawa.ca");
      $query3 = mysqli_query($db,"SELECT email FROM users WHERE username='$username' AND password='$password'");
      $row= mysqli_fetch_array($query3);
      $email = $row['email'];
      $mail->addAddress($email);
      $mail->Subject = 'Verification'; // Give the email a subject 
      $mail->Body = '
        
      This is your verification password
        
      ------------------------
      Password: '.$epassword.'
      ------------------------
      
        
      '; // Our message above including the link
                            
      //$headers = 'From:noreply@yourwebsite.com' . "\r\n"; // Set from headers
      //mail($to, $subject, $message, $headers); // Send our email
      if(!$mail->send()){
        echo "Message could not be sent";
      } else {
        echo "Message has been sent";
      }
      $_SESSION['username'] = $username;
      $_SESSION['success'] = "You are now logged in";
      header('location: verification.php');
      //////////////////////////////////////////////////////////////////////////////////////
      
      
  	}else {
  		array_push($errors, "Wrong username/password combination");
  	}
  }
}

?>
