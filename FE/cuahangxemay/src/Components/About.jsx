import messages from "./Helpers/Messages.jsx";
import React from "react";

export default function About() {
  return (
    <div className="w-full">
      {/* Hero Section */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <h1 className="text-6xl text-center text-blue-600 font-bold">01</h1>
        <h1 className="text-4xl uppercase text-center mb-10 font-bold">
          Chào mừng <span className="text-blue-600">T-Motoshop</span>
        </h1>

        <div className="flex justify-center">
          <div className="max-w-4xl text-center">
            <img
              className="w-3/4 mx-auto mb-6"
              src="/assets/user/Image/Honda/xeSo/header_honda_CBR.jpg"
              alt="Honda CBR"
            />
            <p className="text-gray-700">Nội dung giới thiệu cửa hàng...</p>
          </div>
        </div>

        {/* Feature Boxes */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-8">
          {/* Box 1 */}
          <div className="flex items-center bg-gray-100 p-6 mb-4 h-40">
            <div className="flex items-center justify-center flex-shrink-0 bg-blue-600 -ml-8 mr-6 w-24 h-24">
              <i className="fa fa-2x fa-headset text-gray-200"></i>
            </div>
            <h4 className="uppercase font-bold">{messages.ho_tro}</h4>
          </div>

          {/* Box 2 */}
          <div className="flex items-center bg-gray-800 p-6 mb-4 h-40">
            <div className="flex items-center justify-center flex-shrink-0 bg-blue-600 -ml-8 mr-6 w-24 h-24">
              <i className="fa fa-2x fa-car text-gray-200"></i>
            </div>
            <h4 className="uppercase text-white font-bold">
              {messages.xem_xe}
            </h4>
          </div>

          {/* Box 3 */}
          <div className="flex items-center bg-gray-100 p-6 mb-4 h-40">
            <div className="flex items-center justify-center flex-shrink-0 bg-blue-600 -ml-8 mr-6 w-24 h-24">
              <i className="fa fa-2x fa-map-marker-alt text-gray-200"></i>
            </div>
            <h4 className="uppercase font-bold">{messages.chi_nhanh}</h4>
          </div>
        </div>
      </div>

      {/* Promotional Section */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Promo 1 */}
          <div className="px-6 bg-gray-800 flex items-center justify-between">
            <img
              className="w-1/2 h-auto -ml-6 mr-4 flex-shrink-0"
              src="/assets/user/Image/Honda/xeSo/Win_trang.png"
              alt="Honda Win"
            />
            <div className="text-right py-8">
              <h3 className="uppercase text-white mb-4 font-bold">
                {messages["ban_co_muon"]}
              </h3>
              <p className="mb-6 text-gray-300">
                {messages["content_bancomuon"]}
              </p>
              <a
                className="bg-blue-600 hover:bg-blue-700 text-white py-2 px-6 rounded-sm"
                href=""
              >
                {messages["tham_gia_ngay"]}
              </a>
            </div>
          </div>

          {/* Promo 2 */}
          <div className="px-6 bg-gray-900 flex items-center justify-between">
            <div className="text-left py-8">
              <h3 className="uppercase text-white mb-4 font-bold">
                {messages["lai_thu"]}
              </h3>
              <p className="mb-6 text-gray-300">
                {messages["content_bancomuon"]}
              </p>
              <a
                className="bg-blue-600 hover:bg-blue-700 text-white py-2 px-6 rounded-sm"
                href=""
              >
                {messages["tham_gia_ngay"]}
              </a>
            </div>
            <img
              className="w-1/2 h-auto -mr-6 ml-4 flex-shrink-0"
              src="/assets/user/Image/Honda/tayga/Sh160_special.png"
              alt="Honda SH160"
            />
          </div>
        </div>
      </div>

      {/* Partners/Vendors Carousel */}
      <div className="w-full py-12 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
            <div className="bg-white p-4 flex items-center justify-center">
              <img
                src="/assets/user/Image/Honda/logo-vinfast.png"
                alt="Vinfast"
                className="max-h-20"
              />
            </div>
            <div className="bg-white p-4 flex items-center justify-center">
              <img
                src="/assets/user/Image/Honda/suzuki.png"
                alt="Suzuki"
                className="max-h-20"
              />
            </div>
            <div className="bg-white p-4 flex items-center justify-center">
              <img
                src="/assets/user/Image/Honda/logo_ducati.png"
                alt="Ducati"
                className="max-h-20"
              />
            </div>
            <div className="bg-white p-4 flex items-center justify-center">
              <img
                src="/assets/user/Image/Honda/yamaha.png"
                alt="Yamaha"
                className="max-h-20"
              />
            </div>
            <div className="bg-white p-4 flex items-center justify-center">
              <img
                src="/assets/user/Image/Honda/piago.png"
                alt="Piaggio"
                className="max-h-20"
              />
            </div>
            <div className="bg-white p-4 flex items-center justify-center">
              <img
                className="w-28 h-28"
                src="/assets/user/Image/Honda/logohonda2.png"
                alt="Honda"
              />
            </div>
            <div className="bg-white p-4 flex items-center justify-center">
              <img
                src="/assets/user/img/vendor-7.png"
                alt="Vendor 7"
                className="max-h-20"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
