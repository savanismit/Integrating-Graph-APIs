function changeFunc() {
var selectBox = document.getElementById("selectBox");
var selectedValue = selectBox.options[selectBox.selectedIndex].value;

if (selectedValue=="Scheduled"){
$('#1').show();
$('#2').show();
$('#reply1').show();
$('#reply2').show();
}

else if (selectedValue=="Disabled"){
$('#reply1').hide();
$('#reply2').hide();
$('#1').hide();
$('#2').hide();
}

else {
$('#1').hide();
$('#2').hide();
$('#reply1').show();
$('#reply2').show();
}
}