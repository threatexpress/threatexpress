
// Open image in new window on click
$( "img" ).on( "click",  function() {
    window.open(this.src);
});

// Change cursor over images on mouseover
$( "img" ).on( "mouseover",  function() {
    this.style.cursor='pointer';
    
});

// Open external links in new window (mostly stolen code, ha)
$('a').each(function() {
   var a = new RegExp('/' + window.location.host + '/');
   if(!a.test(this.href)) {
       $(this).click(function(event) {
           event.preventDefault();
           event.stopPropagation();
           window.open(this.href, '_blank');
       });
   }
});

