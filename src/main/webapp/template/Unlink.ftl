<!DOCTYPE html>
<head>
  <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=PT+Serif+Caption" /><link rel='stylesheet' href='//fonts.googleapis.com/css?family=Bevan' type='text/css' />
  <#include "/incs/meta.ftl">
  <#include "/incs/css.ftl">
  <#include "/incs/js.ftl">
</head>
<body>
<style type="text/css">
       #enter {
		 	background-color: #16284C;
		}
    </style>
<#include "/incs/header.ftl">
<#include "/incs/banner.ftl">
<div class="customContainer" style="margin-bottom: 15%">
  <h2 style="text-align: center; padding-top: 4%; padding-bottom: 7%; font-family: Georgia, serif">Unlink</h2>
  <form name="form5" method="post">
    <div class="input-group mb-3" style="padding-left: 10%; padding-right: 10%">
      <div class="input-group-prepend">
        <label class="input-group-text" for="inputGroupSelect01">Client</label>
      </div>
      <select class="custom-select" id="unClient" name="unClient">
        <option selected>Choose...</option>
        <#list clients as client>
        <option>${client}</option>
      </#list>
      </select>
      <div class="input-group-append">
        <button class="btn btn-primary" type="button" id ="unlinkbutton">Unlink</button>
      </div>
    </div>
  </form>
</div>
<#include "/incs/footer.ftl">
</body>
<script>
$(function(){
    $("#unlinkbutton").click(function(){
        var client=document.getElementById("unClient");
	      var index=client.selectedIndex;
	      var clientID=client.options[index].value;
	      if (index==0){
		      alert("Please Choose a Client!");
		      return;
		    }
        $.ajax({
            url : "/oauth2/unlink",
            type : "POST",
            data : "client=" + clientID,
            success : function(data){
                window.location.href = "/resource/user";
            }
        });
    })
});
</script>
</html>