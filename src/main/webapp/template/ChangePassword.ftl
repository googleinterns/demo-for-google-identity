<!DOCTYPE html>
<head>
  <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=PT+Serif+Caption" /><link rel='stylesheet' href='//fonts.googleapis.com/css?family=Bevan' type='text/css' />
  <#include "/incs/meta.ftl">
  <#include "/incs/css.ftl">
  <#include "/incs/js.ftl">
</head>
<body>
<#include "/incs/header.ftl">
<#include "/incs/banner.ftl">
<div id="loginContainer">
  <div class="customContainer">
    <h2 style="text-align: center; font-family: Georgia, serif">Google Account Linking Demo System</h2>
    <h3 style="text-align: center; padding-bottom: 8%; font-family: Georgia, serif">Change Password</h2>
      <div class="row">
        <div class="col-md-4"></div>
        <div class="col-md-4">
          <form id="msform">
            <div class="form-group" style="margin-bottom: 10px">
              <label id="login_label0" style="text-align: left;color: #FC1B10;">New Password</label><br>
              <input class="form-control" name="lname" id="password" type="password" placeholder="New Password">
            </div>
            <div class="form-group" style="margin-bottom: 10px">
              <label id="login_label1" style="text-align: left;color: #FC1B10;">Confirm New Password</label><br>
              <input class="form-control" name="rname" id="cpassword" type="password" placeholder="Confirm New Password">
            </div>
            <div class="row" style="margin-top: 7%">
              <div class="col-6">
                <button class="btn1" type="button" id="confirm" value="Confirm">Confirm</button>
              </div>
              <div class="col-6">
                <button class="btn1 float-sm-right" type="button" id="Cancel" value="Cancel" onclick="location.href='/resource/user'">Cancel</button>
              </div>
            </div>
          </form>
        </div>
      </div>
  </div>
</div>
<#include "/incs/footer.ftl">
</body>
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/rollups/sha256.js"></script>
<script type="text/javascript" >
    $(function(){
    $("#confirm").click(function(){
        var password = $("#password").val();
        var cpassword = $("#cpassword").val();
        if (password != cpassword) {
          alert("Passwords are not same!");
          window.location.reload();
          return;
        }

        password = CryptoJS.SHA256(password);
        var url = '/resource/user/change_password';
        $.ajax({
            url : "/resource/user/change_password",
            type : "POST",
            data : "password=" +password,
            success : function(data){
                window.location.href = data;
            },
            error : function(xhr){
                alert("Failed!");
                window.location.href = "/resource/user"
            }
        });
    })
});
</script>
</html>