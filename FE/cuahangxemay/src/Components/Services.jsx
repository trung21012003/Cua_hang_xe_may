import React from "react";
import messages from "./Helpers/Messages.jsx";

const Services = () =>{
    return(
        <div>
            <div className="container-fluid py-1">
                <div className="container pt-1 pb-3">
                    <h1 className=" display-1 text-primary text-center">02</h1>
                    <h1 className="display-4 text-uppercase text-center mb-5">{messages["dich_vu"]}</h1>
                    <div className="row">
                        {[
                            {
                                id: "01",
                                icon: ["fa-cycle", "fa-cogs"],
                                title: "phu_kien",
                                content: "content_phukien"
                            },
                            {
                                id: "02",
                                icon: ["fa-money-check-alt"],
                                title: "bao_hiem",
                                content: "content_baohiem",
                                active: true
                            },
                            {
                                id: "03",
                                icon: ["fa-motorcycle"],
                                title: "kiem_tra_dinh_ki",
                                content: "content_kiemtradinhki"
                            },
                            {
                                id: "04",
                                icon: ["fa-screwdriver-wrench"],
                                title: "sua_chua_nang_cap",
                                content: "content_suachuanangcap"
                            },
                            {id: "05", icon: ["fa-spray-can"], title: "bao_hanh", content: "content_baohanh"},
                            {id: "06", icon: ["fa-pump-soap"], title: "rua_xe", content: "content_ruaxe"},
                        ].map((service) => (
                            <div key={service.id} className="col-lg-4 col-md-6 mb-2">
                                <div
                                    className={`service-item d-flex flex-column justify-content-center px-4 mb-4 ${service.active ? "active" : ""}`}>
                                    <div className="d-flex align-items-center justify-content-between mb-3">
                                        <div
                                            className="d-flex align-items-center justify-content-center bg-primary ml-n4"
                                            style={{width: "80px", height: "80px"}}
                                        >
                                            {service.icon.map((icon, index) => (
                                                <i key={index}
                                                   className={`fa fa-2x ${icon} text-secondary`}></i>
                                            ))}
                                        </div>
                                        <h1 className="display-2 text-white mt-n2 m-0">{service.id}</h1>
                                    </div>
                                    <h4 className="text-uppercase mb-3">{messages[service.title]}</h4>
                                    <p className="m-0">{messages[service.content]}</p>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    )
}
export default Services;