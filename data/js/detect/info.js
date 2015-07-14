var info_detect = {};

// Synchronous call to gather basic browser information
info_detect.basicInfo = function(){
	var capture_info = {};

	function capture_js(){
	  [
	    "appCodeName",
	    "appMinorVersion",
	    "appName",
	    "appVersion",
	    "browserLanguage",
	    "buildID",
	    "cookieEnabled",
	    "cpuClass",
	    "doNotTrack",
	    "hardwareConcurrency",
	    "language",
	    "languages",
	    "maxTouchPoints",
	    "msDoNotTrack",
	    "oscpu",
	    "platform",
	    "product",
	    "productSub",
	    "systemLanguage",
	    "userAgent",
	    "userLanguage",
	    "vendor",
	    "vendorSub",
	  ].forEach(function(k) {
	    if (window.navigator[k]) capture_store("nav", k, window.navigator[k]);
	  });

	  if (window.navigator.battery) {
	    [
	      "charging",
	      "chargingTime",
	      "dischargingTime",
	      "level"
	    ].forEach(function(k) {
	      if (window.navigator.battery[k]) capture_store("nav_battery", k, window.navigator.battery[k]);
	    });
	  }

	  if (window.navigator.metered) {
	    [
	      "bandwidth",
	      "metered"
	    ].forEach(function(k) {
	      if (window.navigator.connection[k]) capture_store("nav_connection", k, window.navigator.connection[k]);
	    });
	  }

	  var capture_date = new Date();
	  capture_store("time", "stamp", capture_date.getTime());
	  capture_store("time", "offset", capture_date.getTimezoneOffset());
	  [
	    "top",
	    "left",
	    "height",
	    "width",
	    "colorDepth",
	    "pixelDepth",
	    "availHeight",
	    "availWidth",
	    "availTop",
	    "availLeft",
	    "mozBrightness",
	  ].forEach(function(k) {
	    if (window.screen[k]) capture_store("screen", k, window.screen[k]);
	  });

	  for(var i = 0; i < window.navigator.plugins.length; i++){
	    var p = window.navigator.plugins[i];
	    [
	      "name",
	      "filename",
	      "version",
	      "description"
	    ].forEach(function(a){
	      capture_store("plugins", i+"_"+a, p[a]);
	    });
	  }
	}

	function capture_create_gl(){
	  if (!window.WebGLRenderingContext) return;
	  var capture_canvas = document.createElement('canvas');
	  var capture_gl = false;
	  [
	    "webgl",
	    "experimental-webgl",
	    "moz-webgl",
	    "webkit-3d"
	  ].some(function(webgl_context){
	    try {
	      capture_gl = capture_canvas.getContext(webgl_context);
	      if (capture_gl) return true;
	    } catch(e) {}
	  });
	  return capture_gl;
	}

	function capture_gl(){
	  var capture_gl = capture_create_gl();
	  if (!capture_gl) return;
	  [
	    'VENDOR',
	    'RENDERER',
	    'VERSION',
	    'SHADING_LANGUAGE_VERSION'
	  ].forEach(function(k) {
	    var val = capture_gl.getParameter(eval("capture_gl." + k));
	    if (val) capture_store('webgl', k.toLowerCase(), val);
	  });

	  var capture_extension = capture_gl.getExtension('WEBGL_debug_renderer_info');
	  if (capture_extension != undefined) {
	    capture_store('webgl','unmasked_renderer', capture_gl.getParameter(capture_extension.UNMASKED_RENDERER_WEBGL));
	    capture_store('webgl','unmasked_vendor', capture_gl.getParameter(capture_extension.UNMASKED_VENDOR_WEBGL));
	  }
	}

	function capture_opera() {
	  if (! window.opera) return;
	  capture_store('opera','version', window.opera.version());
	  capture_store('opera','buildNumber', window.opera.buildNumber('inconspicuous'));
	}

	function capture_ie() {
	  if (typeof ScriptEngineMajorVersion != "function") return;
	  capture_store('ie','version_major', ScriptEngineMajorVersion());
	  capture_store('ie','version_minor', ScriptEngineMinorVersion());
	  capture_store('ie','version_build', ScriptEngineBuildVersion());
	}

	function capture_store(group, name, value) {
	  capture_info[group + "_" + name] = String(value);
	}

	capture_js();
	capture_ie();
	capture_opera();
	capture_gl();

	return capture_info;
};
