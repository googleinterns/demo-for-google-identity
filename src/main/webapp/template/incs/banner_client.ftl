<div id="grad"></div>
<nav class="navbar navbar-expand-md" style="background-color: #0E5BB1; color:white; padding: 0%">


  <div id="mobileSign">
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNavDropdown" aria-controls="navbarNavDropdown" aria-expanded="false" aria-label="Toggle navigation" style="font-size: 16px;">
      <span class="navbar-toggler-icon" id="toggleIcon" ></span>
    </button>

  </div>

  <div class="navbar-collapse collapse" id="navbarNavDropdown" style="margin-left:3%; margin-right:3%">
    <ul class="navbar-nav mr-auto">
      <li class="nav-item">
        <a class="nav-link" href="/client/change_setting" id="change">Change Setting</a>
      </li>
    </ul>
    <ul class="navbar-nav ml-md-auto d-md-flex">
      <li class="nav-item2 dropdown">
        <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
          <i class="fas fa-user-circle fa-fw"></i>
          ${clientID}
        </a>
        <div class="dropdown-menu" aria-labelledby="userDropdown">
          <a class="dropdown-item" href="/logout">Logout</a>
        </div>
      </li>
    </ul>
  </div>
</nav>