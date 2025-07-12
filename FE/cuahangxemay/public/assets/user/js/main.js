(function ($) {
    "use strict";

    // Dropdown on mouse hover
    $(document).ready(function () {
        function toggleNavbarMethod() {
            if ($(window).width() > 992) {
                $('.navbar .dropdown').on('mouseover', function () {
                    $('.dropdown-toggle', this).trigger('click');
                }).on('mouseout', function () {
                    $('.dropdown-toggle', this).trigger('click').blur();
                });
            } else {
                $('.navbar .dropdown').off('mouseover').off('mouseout');
            }
        }
        toggleNavbarMethod();
        $(window).resize(toggleNavbarMethod);
    });
    // Date and time picker
    $('.date').datetimepicker({
        formatDate: 'dd-mm-yyyy'
    });
    $('.time').datetimepicker({
        format: ''
    });
    
    
    // Back to top button
    $(window).scroll(function () {
        if ($(this).scrollTop() > 100) {
            $('.back-to-top').fadeIn('slow');
        } else {
            $('.back-to-top').fadeOut('slow');
        }
    });
    $('.back-to-top').click(function () {
        $('html, body').animate({scrollTop: 0}, 1500, 'easeInOutExpo');
        return false;
    });


    // Team carousel
    $(".team-carousel, .related-carousel").owlCarousel({
        autoplay: true,
        smartSpeed: 1000,
        center: true,
        margin: 30,
        dots: false,
        loop: true,
        nav : true,
        navText : [
            '<i class="fa fa-angle-left" aria-hidden="true"></i>',
            '<i class="fa fa-angle-right" aria-hidden="true"></i>'
        ],
        responsive: {
            0:{
                items:1
            },
            576:{
                items:1
            },
            768:{
                items:2
            },
            992:{
                items:3
            }
        }
    });


    // Testimonials carousel
    $(".testimonial-carousel").owlCarousel({
        autoplay: true,
        smartSpeed: 1500,
        margin: 30,
        dots: true,
        loop: true,
        center: true,
        responsive: {
            0:{
                items:1
            },
            576:{
                items:1
            },
            768:{
                items:2
            },
            992:{
                items:3
            }
        }
    });


    // Vendor carousel
    $('.vendor-carousel').owlCarousel({

        margin: 30,
        dots: true,
        loop: true,
        center: true,
        autoplay: true,
        smartSpeed: 1000,
        responsive: {
            0:{
                items:2
            },
            576:{
                items:3
            },
            768:{
                items:4
            },
            992:{
                items:5
            },
            1200:{
                items:6
            }
        }
    });
    
})(jQuery);
// loader
let loader = document.getElementById("preloader");
        window.addEventListener("load", function(){
            loader.style.display = "none";
})

window.onscroll = function() {myFunction()};
var header = document.getElementById("myHeader");
var topheader = document.getElementsByClassName("top-header-1");
var sticky = header.offsetTop;
var sticky2 = topheader.offsetTop;
function myFunction() {
  if (window.pageYOffset > sticky) {
    header.classList.add("sticky");
  } else {
    header.classList.remove("sticky");
   
  }
}
// Returns an array of maxLength (or less) page numbers
// where a 0 in the returned array denotes a gap in the series.
// Parameters:
//   totalPages:     total number of pages
//   page:           current page
//   maxLength:      maximum size of returned array
function getPageList(totalPages, page, maxLength) {
  if (maxLength < 5) throw "maxLength must be at least 5";

  function range(start, end) {
      return Array.from(Array(end - start + 1), (_, i) => i + start); 
  }

  var sideWidth = maxLength < 9 ? 1 : 2;
  var leftWidth = (maxLength - sideWidth*2 - 3) >> 1;
  var rightWidth = (maxLength - sideWidth*2 - 2) >> 1;
  if (totalPages <= maxLength) {
      // no breaks in list
      return range(1, totalPages);
  }
  if (page <= maxLength - sideWidth - 1 - rightWidth) {
      // no break on left of page
      return range(1, maxLength - sideWidth - 1)
          .concat(0, range(totalPages - sideWidth + 1, totalPages));
  }
  if (page >= totalPages - sideWidth - 1 - rightWidth) {
      // no break on right of page
      return range(1, sideWidth)
          .concat(0, range(totalPages - sideWidth - 1 - rightWidth - leftWidth, totalPages));
  }
  // Breaks on both sides
  return range(1, sideWidth)
      .concat(0, range(page - leftWidth, page + rightWidth),
              0, range(totalPages - sideWidth + 1, totalPages));
}

// Below is an example use of the above function.
$(function () {
  // Number of items and limits the number of items per page
  var numberOfItems = $(".list .item").length;
  var limitPerPage = 12;
  // Total pages rounded upwards
  var totalPages = Math.ceil(numberOfItems / limitPerPage);
  // Number of buttons at the top, not counting prev/next,
  // but including the dotted buttons.
  // Must be at least 5:
  var paginationSize = 7; 
  var currentPage;

  function showPage(whichPage) {
      if (whichPage < 1 || whichPage > totalPages) return false;
      currentPage = whichPage;
      $(".list .item").hide()
          .slice((currentPage-1) * limitPerPage, 
                  currentPage * limitPerPage).show();
      // Replace the navigation items (not prev/next):            
      $(".listPage li").slice(1, -1).remove();
      getPageList(totalPages, currentPage, paginationSize).forEach( item => {
          $("<li>").addClass("page-item")
                   .addClass(item ? "current-page" : "disabled")
                   .toggleClass("active", item === currentPage).append(
              $("<a>").addClass("page-link").attr({
                  href: "javascript:void(0)"}).text(item || "...")
          ).insertBefore("#next-page");
      });
      // Disable prev/next when at first/last page:
      $("#previous-page").toggleClass("disabled", currentPage === 1);
      $("#next-page").toggleClass("disabled", currentPage === totalPages);
      return true;
  }

  // Include the prev/next buttons:
  $(".listPage").append(
      $("<li>").addClass("page-item").attr({ id: "previous-page" }).append(
          $("<a>").addClass("page-link").attr({
              href: "javascript:void(0)"}).text("Prev")
      ),
      $("<li>").addClass("page-item").attr({ id: "next-page" }).append(
          $("<a>").addClass("page-link").attr({
              href: "javascript:void(0)"}).text("Next")
      )
  );
  // Show the page links
  $(".list").show();
  showPage(1);

  // Use event delegation, as these items are recreated later    
  $(document).on("click", ".listPage li.current-page:not(.active)", function () {
      return showPage(+$(this).text());
  });
  $("#next-page").on("click", function () {
      return showPage(currentPage+1);
  });

  $("#previous-page").on("click", function () {
      return showPage(currentPage-1);
  });
});

//valid register
        //show and hidde password
       
        //validate form
        // function checkName() {
            // var inputName = document.getElementById('inputName').value;
            // var error = document.getElementById('error_name');
            // var regexName = /^[^\d+]*[\d+]{0}[^\d+]*$/;
            // if(inputName == '' || inputName == null) {
            //     error.innerHTML = "Họ tên không được để trống "
            // }else if(!regexName.test(inputName)) {
            //     error.innerHTML = "Họ tên không hợp lệ"
            // }else {
            //     error.innerHTML = "";
            // }
            // return name
        // }

        function FormValidate() {
            var name = document.getElementById('inputName').value;
			var errorName = document.getElementById('error_name');
			var regexName = /^[^\d+]*[\d+]{0}[^\d+]*$/; 

            var email = document.getElementById('inputEmail').value;
			var errorEmail = document.getElementById('error-email');
			var reGexEmail = /[A-Z0-9._%+-]+@[A-Z0-9-]+.+.[A-Z]{2,4}/igm;

            var phone = document.getElementById('inputPhone').value;
			var errorPhone = document.getElementById('error-phone');
			var regexPhone = /^(0?)(3[2-9]|5[6|8|9]|7[0|6-9]|8[0-6|8|9]|9[0-4|6-9])[0-9]{7}$/;
            // valid name           
            if(name == '' || name == null) {
                errorName.innerHTML = "Họ tên không được để trống "
            }else if(!regexName.test(name)) {
                errorName.innerHTML = "Họ tên không hợp lệ"
            }else {
                errorName.innerHTML = "";
            }
            //valid email 
            if (email == '' || email == null) {
				errorEmail.innerHTML = "Email không được để trống!";
			}else if(!reGexEmail.test(email)){
				errorEmail.innerHTML = "Email không hợp lệ!";
				email = '';
			}else{
				errorEmail.innerHTML = '';
			}
            //valid phone
             if(!regexPhone.test(phone) && !phone == null){
				errorPhone.innerHTML = "SĐT không hợp lệ!";
				return false;
			}else{
				errorPhone.innerHTML = '';
			}
            //valid password 
            var passW = document.getElementById('inputPassword').value;
			var errorPass = document.getElementById('error-password');

			if (passW == '' || passW == null) {
				errorPass.innerHTML = "Mật khẩu vui lòng không để trống!";
			}else{
				errorPass.innerHTML = "";
			}

			var ConPass = document.getElementById('inputConPass').value;
			var errorConPass = document.getElementById('error-ConPass');

			if (ConPass == '' || ConPass == null) {
				errorConPass.innerHTML = "Xác nhận mật khẩu vui lòng không để trống!";
			}else if(ConPass != passW){
				errorConPass.innerHTML= ("Xác nhận mật khẩu không trùng khớp!");
                
			}else{
				errorConPass.innerHTML = "";
			}

			if ((name && phone && email && ConPass && passW && passW == ConPass) || (name && email && ConPass && passW && passW == ConPass) ) {
				// Người dùng đã nhập đúng thông tin
				alert("Đăng ký thành công!");
				window.location.href= "login.html";
				// return true; thực hiện việc submit form
                // showSuccessToast();
                // toast();
			}
			return false;
        }    
function favoriteProduct() {
    var fill = document.getElementById("heart")
    var nofill = document.getElementById("heart-nofill");
    if (fill.style.display !== "none") {
        fill.style.display = "none"
        nofill.style.display = "inline-block";
    } else {
        nofill.style.display = "none"
        fill.style.display = "inline-block";
    }
}
function showImage(imageSrc) {
    var largeDiv = document.getElementById('largeDiv');
    var largeImage = document.getElementById('largeImage');

    largeImage.src = imageSrc;
    largeDiv.style.display = 'block';
}