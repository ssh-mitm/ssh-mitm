
$(window).on('load resize', function() {

    //Add/remove class based on browser size when load/resize
    var w = $(window).width();

	if(w >= 1200) {
	    // if larger
	    $('#docs-sidebar').addClass('sidebar-visible').removeClass('sidebar-hidden');
	} else {
	    // if smaller
	    $('#docs-sidebar').addClass('sidebar-hidden').removeClass('sidebar-visible');
	}
});


$(document).ready(function() {

	/* ====== Toggle Sidebar ======= */

	$('#docs-sidebar-toggler').on('click', function(){

		if ( $('#docs-sidebar').hasClass('sidebar-visible') ) {

			  $("#docs-sidebar").removeClass('sidebar-visible').addClass('sidebar-hidden');


		} else {

			  $("#docs-sidebar").removeClass('sidebar-hidden').addClass('sidebar-visible');

		}

    });



});