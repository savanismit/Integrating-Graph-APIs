$("#menu-toggle").click(function(e) {
      e.preventDefault();
      $("#wrapper").toggleClass("toggled");
    });

function show_modal(ele){
    id = ele.id.split("_")[1] - 1;

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