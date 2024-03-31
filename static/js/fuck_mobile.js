function fuck_mobile(x){
    // site is mobile
    if(x.matches){
        console.log("MATCH");
        document.querySelector("body").innerHTML = "Get the Fuck out. Fuck mobile sites, scaling in CSS is wayyy too fucking painful<br><img src='/images/fuck_off.jpg' height = 500px>"

    }else{
        console.log("NOPE ");
    }
}
var x = window.matchMedia("(max-width: 700px)")
fuck_mobile(x);

x.addEventListener("change", function() {
  fuck_mobile(x);
});
