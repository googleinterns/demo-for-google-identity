<!DOCTYPE html>
<head>
  <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=PT+Serif+Caption" /><link rel='stylesheet' href='//fonts.googleapis.com/css?family=Bevan' type='text/css' />
  <#include "/incs/meta.ftl">
  <#include "/incs/css.ftl">
  <#include "/incs/js.ftl">
</head>
<body>
<#include "/incs/header.ftl">
<#include "/incs/banner_client.ftl">
<div id="loginContainer">
  <div class="customContainer">
    <h2 style="text-align: center; font-family: Georgia, serif">Google Account Linking Demo System</h2>
    <h3 style="text-align: center; padding-bottom: 8%; font-family: Georgia, serif">Change Setting</h2>
      <div class="row">
        <div class="col-md-4"></div>
        <div class="col-md-4">
          <form id="msform">
            <div class="form-group" style="margin-bottom: 10px">
              <label id="login_label0" style="text-align: left;color: #2177F3;">Secret</label><br>
              <input class="form-control" name="rname" id="secret" type="text" placeholder="Secret" >
            </div>
            <div class="form-group" style="margin-bottom: 10px">
              <label id="login_label1" style="text-align: left;color: #2177F3;">Grant Types(split with ;)</label><br>
              <input class="form-control" name="rname" id="grant_types" type="text" placeholder="Grant Types" value=${grant_types}>
            </div>
            <div class="form-group" style="margin-bottom: 10px">
              <label id="login_label2" style="text-align: left;color: #2177F3;">Scopes(split with ;)</label><br>
              <input class="form-control" name="rname" id="scopes" type="text" placeholder="Scopes" value=${scopes}>
            </div>
            <div class="form-group" style="margin-bottom: 10px">
              <label id="login_label3" style="text-align: left;color: #2177F3;">Redirect Uris(split with ;)</label><br>
              <input class="form-control" name="rname" id="redirect_uris" type="text" placeholder="Redirect Uris" value=${redirect_uris}>
            </div>
            <div class="form-group" style="margin-bottom: 10px">
              <label id="login_label4" style="text-align: left;color: #2177F3;">Risc Uri</label><br>
              <input class="form-control" name="rname" id="risc_uri" type="text" placeholder="Risc uri" value=${risc_uri}>
            </div>
            <div class="form-group" style="margin-bottom: 10px">
              <label id="login_label5" style="text-align: left;color: #2177F3;">Risc aud</label><br>
              <input class="form-control" name="rname" id="risc_aud" type="text" placeholder="Risc aud" value=${risc_aud}>
            </div>
            <div class="row" style="margin-top: 7%">
              <div class="col-6">
                <button class="btn1" type="button" id="confirm" value="Confirm">Confirm</button>
              </div>
              <div class="col-6">
                <button class="btn1 float-sm-right" type="button" id="Cancel" value="Cancel" onclick="location.href='/client'">Cancel</button>
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
        var secret = $("#secret").val();
        var scopes = $("#scopes").val();
        var grant_types = $("#grant_types").val();
        var redirect_uris = $("#redirect_uris").val();
        var risc_uri = $("#risc_uri").val();
        var risc_aud = $("#risc_aud").val();
        if (secret == "") {
          alert("Secret cannot be empty!");
          window.location.reload();
          return;
        }
        if (grant_types == "") {
          alert("grantType cannot be empty!");
          window.location.reload();
          return;
        }

        if (redirect_uris == "") {
          alert("redirect uris cannot be empty!");
          window.location.reload();
          return;
        }
        secret = CryptoJS.SHA256(secret);
        $.ajax({
            url : "/client/change_setting",
            type : "POST",
            data : "secret=" +secret+"&grant_types="+grant_types+"&scopes=" +scopes+"&redirect_uris="+redirect_uris+"&risc_uri="+risc_uri+"&risc_aud="+risc_aud,
            success : function(data){
                window.location.href = data;
            },
            error : function(xhr){
                alert("Failed!");
                window.location.href = "/client"
            }
        });
    })
});
</script>
</html>