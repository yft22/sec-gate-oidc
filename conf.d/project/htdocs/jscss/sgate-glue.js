var idpsdiv;

function addOneIdp (div_box, idp) {

    // create a new dic for this IDP
    var idp_box= document.createElement("div");
    div_box.appendChild(idp_box);
    idp_box.setAttribute("id", idp.uid);
    div_box.className="sgate_idp";

    // add icon
    var logo= document.createElement('img');
    idp_box.appendChild(logo)
    logo.src= idp.logo;
    logo.className= "sgate_logo";

    // add login button
    var button = document.createElement("button");
    idp_box.appendChild(button)
    button.className= "sgate_button";
    button.innerText= idp.uid;
    button.onclick= function() {
        location.href= idp["login-url"];
    }

    // add idp info text
    var info= document.createElement('span');
    info.className= "sgate_info";
    idp_box.appendChild(info)
    info.innerHTML = idp.info;
}

// get IDPs list from oidc-sgate
function getIdps() {

    // ws.call return a Promise
    var api="sgate";
    var verb="idp-list";
    var query="{}";
    log.command(api, verb, query);   
    ws.call(api + "/" + verb, query)
    .then(function (res) {
        log.reply(res);
        var div_box;
        var sgate_div= document.getElementById("sgate_div");
        sgate_div.className="sgate_box";

        if (sgate_div === null) {
            window.alert("getIdps() requirer <div id='sgate_div'> in page");
            return; 
        }

        // when exit add alias info data
        if (res.response.alias) {
            div_box= document.createElement("div");
            div_box.id="alias_json";
            div_box.className="sgate_extra";
            div_box.innerText= "Request: " + JSON.stringify(res.response.alias);
            sgate_div.appendChild(div_box); 
        }        

        // add all IDP in a share div
        div_box= document.createElement("div");
        div_box.id="idps_box";
        for (const idp of res.response.idps) {
            addOneIdp(div_box, idp);
        }
        sgate_div.appendChild(div_box);

    })
    .catch(function (err) {
        log.reply(err);
    });
} 

// get IDPs list from oidc-sgate
function getSession() {

    // ws.call return a Promise
    var api="sgate";
    var verb="get-session";
    var query="{}";
    log.command(api, verb, query);   
    ws.call(api + "/" + verb, query)
    .then(function (res) {
        log.reply(res);

        var form= document.getElementById ("register_user");
        if (form === null) {
            window.alert("getSession() requirer <form id='register_user'> in page");
           return; 
        }

        // loop on every object field and update value when exit 
        // res.response[0] => social user definition
        // res.response[1] => idp & loa 
        // res.response[2] => used scope
        for (const [key, value] of Object.entries(res.response[0])) {
            var idx;
            var input= document.getElementById (key);
            if (input) {
                input.value= value;
            }
        }

    })
    .catch(function (err) {
        log.reply(err);
    });
} 

function registerUser() {

    // make sure form id march with html page
    var form= document.getElementById ("register_user");
    if (form === null) {
        window.alert("registerUser() requirer <form id='register_user'> in page");
        return; 
    }

    // retrieve value from HTML form
    var query={};
    for (var idx= 0; idx < form.length ;idx++) {
        var uid= form[idx].id;
        var value= form[idx].value;
        if (value) {
            query[uid]=value;
        }
    } 

    // call user-registration
    var api="sgate";
    var verb="usr-register";
    log.command(api, verb, query);   
    ws.call(api + "/" + verb, query)
    .then(function (res) {
        log.reply(res);
        // redirect to requested URL
        window.location.replace(res.response.target);

    })
    .catch(function (err) {
        log.reply(err);
        var info= document.getElementById("register_info");
        if (info === null) {
           window.alert("registerUser() requirer <span id='register_info'> in page");
           return; 
        }
        info.innerHTML= JSON.stringify(err);
    });

}