<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login</title>
    <link rel='stylesheet' href='../css/bootstrap.min.css' >
    <style>
            .container{
                display:table;
                height:100%;
            }

            .row{
                display: table-cell;
                vertical-align: middle;
            }
            .row-centered {
                text-align:center;
            }
            .col-centered {
                display:inline-block;
                float:none;
                text-align:left;
                margin-right:-4px;
            }
        </style>
</head>
<body>
<div class="container">
    <div class="row row-centered">
        <div class="well col-md-6 col-centered">
            <div style="text-align:center">
            <h2>Login</h2>
            </div>
            <form action="/login_check" method="post" role="form">
                <div class="input-group input-group-md">
                    <input type="text" class="form-control" id="username" name="username" placeholder="username"/>
                </div>
                <div class="input-group input-group-md">
                    <input type="password" class="form-control" id="password" name="password" placeholder="password"/>
                </div>
                <br/>
                <button type="submit" class="btn btn-success btn-block">Login</button>
            </form>
        </div>
    </div>
</div>
</body>
</html>