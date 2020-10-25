<?php  if (count($errors) > 0) : ?>
  <div class="error">
  	<?php foreach ($errors as $error) : ?>
  	  <p><?php echo $error ?></p>
      ; Disable displaying errors to screen
display_errors = off
; Enable writing errors to server logs
log_errors = on
  	<?php endforeach ?>
  </div>
<?php  endif ?>