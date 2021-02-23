$("#menu-toggle").click(function(e) {
      e.preventDefault();
      $("#wrapper").toggleClass("toggled");
    });

function show_modal1(ele1){
    id = ele1.id.split("_")[1] - 1;

    var modal = document.getElementById("myModal_"+id);
    modal.style.display = "block";

    var span = document.getElementById("close_tag_"+id);
    span.onclick = function() {
      modal.style.display = "none";
    }

    // When the user clicks anywhere outside of the modal, close it
    window.onclick = function(event) {
      if (event.target == modal) {
        modal.style.display = "none";
      }
    }
}
function show_modal2(ele2){
    id = ele2.id.split("_")[1] - 1;

    var modal = document.getElementById("myModal2_"+id);
    modal.style.display = "block";

    var span = document.getElementById("close_tag2_"+id);
    span.onclick = function() {
      modal.style.display = "none";
    }

    // When the user clicks anywhere outside of the modal, close it
    window.onclick = function(event) {
      if (event.target == modal) {
        modal.style.display = "none";
      }
    }
}

//function Update(e){
//    id = e.id.split("_")[1];
//    var b = document.getElementById('email_'+id).value;
//    console.log(b);
//    document.getElementById('current_email').innerHTML = b;
//}

$(document).ready(function () {
  $('#dtBasicExample').DataTable();
  $('.dataTables_length').addClass('bs-select');
});
