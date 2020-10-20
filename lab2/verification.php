<?php include('server.php') ?>
<!DOCTYPE html>
<html>
<head>
  <title>Registration system PHP and MySQL</title>
  <link rel="stylesheet" type="text/css" href="style.css">
</head>
<body>
  <div class="header">
  	<h2>2 Factor Authentication</h2>
  </div>
	 
  <form method="post" action="verification.php">
  	<?php include('errors.php'); ?>

  	<div class="input-group">
  		<label>Username</label>
  		<input type="text" name="username" >
  	</div>
	  <div class="input-group">
  		<label>Password</label>
  		<input type="text" name="epassword">
  	</div>
  	<div class="input-group">
  		<button type="submit" class="btn" name="verify_user">Verify</button>
  	</div>
	  <p>
  		Check your email and insert your temporary password</a>
  	</p>
  </form>
</body>
</html>