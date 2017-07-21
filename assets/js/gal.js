var $grid

$(function() {

  $grid = $('.grid').isotope({
    layoutMode: 'masonry',
    itemSelector: '.grid-item',
      percentPosition: true,
    masonry: {
    columnWidth: '.grid-sizer'
    }
  });
  
  // getItems function is defined in body.html
  var $items = getItems();
  $grid.isotopeImagesReveal($items);

  $grid.on("click", "img", function(event) {
    var $item = $( event.currentTarget ).parent() ;
    // change size of item by toggling large class
    if ( $item.is('.gigante') ) {
      $item.removeClass('gigante');
      $grid.isotope('layout');
      $('.modshield').fadeOut(250);
    }else{
      $item.addClass('gigante');
      $('.modshield').fadeIn(250);
    };
  });

  $grid.on("mouseenter", ".grid-item", function(event) {
    var $item = $( event.currentTarget ) ;
    $item.find(".edit").show();
  }).on("mouseleave", ".grid-item", function(event) {
    var $item = $( event.currentTarget ) ;
    $item.find(".edit").hide();
  });

  window.addEventListener("orientationchange", function() {
    // Announce the new orientation number
    $grid.isotope('layout');
  }, false);

  // bind filter button click
  $filters = $('#filters').on( 'click', 'button', function() {
    var $this = $( this );
    var filterValue;
    if ( $this.is('.is-checked') ) {
      // uncheck
      filterValue = '*';
    } else {
      filterValue = $this.attr('data-filter');
      $filters.find('.is-checked').removeClass('is-checked');
    }
    $this.toggleClass('is-checked');
  
    $grid.isotope({ filter: filterValue });
  });

});
  
$.fn.isotopeImagesReveal = function($items) {
  
  var iso = $grid.data("isotope");
  var itemSelector = ".grid-item";
  // hide by default
  $items.hide();
  
  // append to container
  this.append($items);
  $items.imagesLoaded().progress(function(imgLoad, image) {
  
    // get item
    // image is imagesLoaded class, not <img>, <img> is image.img
    var $item = $(image.img).parents(itemSelector);
  
    $item.children().ready(function(){
      var $img = $item.children();
      if (($img.naturalWidth >= $img.naturalHeight) || ($img.width() >= $img.height())) {
          $img.parent().addClass("hrzt");
          $img.parent().removeClass("vert");
      } else {
        $img.parent().addClass("vert");
        $img.parent().removeClass("hrzt");
      }
      $grid.isotope('layout');
    });

    // un-hide item
    $item.show();
    
    // isotope does its thing
    iso.appended($item);
  
  });
};