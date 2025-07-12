import { useEffect } from "react";
import { useLocation } from "react-router-dom";

const ScrollRestoration = () => {
  const location = useLocation();

  // Lưu vị trí cuộn khi rời trang
  useEffect(() => {
    const handleScroll = () => {
      sessionStorage.setItem(
        `scrollPosition_${location.pathname}`,
        window.scrollY.toString()
      );
    };

    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, [location.pathname]);

  // Khôi phục vị trí cuộn khi quay lại trang
  useEffect(() => {
    const scrollPosition = sessionStorage.getItem(
      `scrollPosition_${location.pathname}`
    );
    if (scrollPosition) {
      window.scrollTo(0, parseInt(scrollPosition, 10));
    } else {
      window.scrollTo(0, 0); // Cuộn về đầu nếu không có vị trí lưu
    }
  }, [location.pathname]);

  return null;
};
export default ScrollRestoration;
