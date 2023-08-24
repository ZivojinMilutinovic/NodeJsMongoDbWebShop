
const url = "http://localhost:3000/users";
const redirectUrl = "http://localhost:3000/admin/users/index";
window.addEventListener("DOMContentLoaded",()=>{

    const currentUrl = window.location.href;
    var id = currentUrl.substring(currentUrl.lastIndexOf('/') + 1);
    fetch(url+"/"+id,{
        method : 'GET',
        headers: {
            'Content-Type': 'application/json',
          }
    })
    .then(res=>res.json())
    .then(res=>{
        document.getElementById("password").value="";;
        document.getElementById("email").value=res.email;
        document.getElementById("username").value=res.username;
        document.getElementById("is_admin").checked=res.is_admin;
    })
    .catch(err=>console.log("Error happened",err));


    document.getElementById("submit")
    .addEventListener("click",()=>{
    let password = document.getElementById("password").value;
    let email = document.getElementById("email").value;
    let username = document.getElementById("username").value;
    let is_admin = document.getElementById("is_admin").checked;
    if(password==""||email==""||username==""){
        const errorDiv=  document.getElementById("error");
        const errorMessage="This fields can not be empty";
        errorDiv.innerHTML = errorMessage;
        return;
    }
    let obj = {password,email,username,is_admin};
    console.log(obj)
    fetch(url+"/"+id,{
        method : 'PATCH',
        headers: {
            'Content-Type': 'application/json',
          },
        body: JSON.stringify(obj)
    })
    .then(data=>{
        console.log("Success:",data);
        window.location.href = redirectUrl;
    })
    .catch(err=>console.log("Some error has happened",err))
    });


    
});