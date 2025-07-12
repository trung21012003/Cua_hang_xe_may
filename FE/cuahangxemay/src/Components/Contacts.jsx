import React from "react";
import messages from "./Helpers/Messages.jsx";

const Contacts = () =>{
    return(
        <div className="mt-20">
            <div className="container-fluid py-1">
                <div className="container pt-5 pb-3">
                    <h1 className="display-4 text-uppercase text-center mb-5">{messages.lien_he_voi_chung_toi}</h1>
                    <div className="row">
                        <div className="col-lg-7 mb-2">
                            <div className="contact-form bg-light mb-4" id="before" style={{padding: '30px'}}>
                                <form id="formContact">
                                    <div className="d-flex justify-content-center">
                                        <h3>{messages.thong_tin}</h3></div>
                                    <div className="row">
                                        <div className="col-6 form-group">
                                            <input type="text" id="name" name="name" className="form-control p-4"
                                                   placeholder={messages.ten_cua_ban} required/>
                                        </div>
                                        <div className="col-6 form-group">
                                            <input type="email" id="email" name="email" className="form-control p-4"
                                                   placeholder="Email" required/>
                                        </div>
                                    </div>
                                    <div className="form-group">
                                        <input type="text" id="phone" name="phone" className="form-control p-4"
                                               placeholder={messages.so_dien_thoai} required/>
                                    </div>
                                    <div className="form-group">
                                        <textarea className="form-control py-3 px-4" id="content" name="content"
                                                  rows="5" placeholder={messages.yeu_cau_tu_van}
                                                  required></textarea>
                                    </div>
                                    <div>
                                        <button className="btn btn-primary py-3 px-5" id="button"
                                                type="submit">{messages.gui_yeu_cau}</button>
                                    </div>
                                </form>
                            </div>

                            <div className="contact-form bg-light mb-4" id="after"
                                 style={{padding: '30px', display: 'none'}}>
                                <div className="d-flex justify-content-center"><h3>{messages.cam_on}</h3>
                                </div>
                                <div className="row">
                                    <div className="col-6 form-group">
                                        {/*{messages.ten_cua_ban}: <span*/}
                                        {/*id="nameContact">{contactInfo?.name}</span>*/}
                                    </div>
                                    <div className="col-6 form-group">
                                        {/*Email: <span id="emailContact">{contactInfo?.email}</span>*/}
                                    </div>
                                    <div className="col-6 form-group">
                                        {/*{messages.getString("so_dien_thoai")}: <span*/}
                                        {/*id="phoneContact">{contactInfo?.phone}</span>*/}
                                    </div>
                                    <div className="col-6 form-group">
                                        {/*{messages.getString("yeu_cau_tu_van")}: <span*/}
                                        {/*id="contentContact">{contactInfo?.content}</span>*/}
                                    </div>
                                    <button className="btn btn-primary py-3 px-5" id="button2">OK
                                    </button>
                                </div>
                            </div>
                        </div>

                        <div className="col-lg-5 mb-2">
                            <div className="bg-secondary d-flex flex-column justify-content-center px-5 mb-4"
                                 style={{height: '435px'}}>
                                <div className="d-flex mb-3">
                                    <i className="fa fa-2x fa-map-marker-alt text-primary flex-shrink-0 mr-3"></i>
                                    <div className="mt-n1">
                                        <h5 className="text-light">{messages.dia_chi}</h5>
                                        <p>{messages.content_diachi}</p>
                                    </div>
                                </div>

                                <div className="d-flex mb-3">
                                    <i className="fa fa-2x fa-envelope-open text-primary flex-shrink-0 mr-3"></i>
                                    <div className="mt-n1">
                                        <h5 className="text-light">{messages.ho_tro}</h5>
                                        <p>tmotoshop.service@gmail.com</p>
                                    </div>
                                </div>

                                <div className="d-flex">
                                    <i className="fa fa-2x fa-phone text-primary flex-shrink-0 mr-3"></i>
                                    <div className="mt-n1">
                                        <h5 className="text-light"></h5>
                                        <p className="m-0">0326767031</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div className="container-fluid py-1">
                <div className="container pt-3 pb-3">
                    <h1 className="display-1 text-primary text-center">06</h1>
                    <h1 className="display-4 text-uppercase text-center mb-5">{messages.han_hanh}</h1>
                    <div className="row">
                        <div className="col-lg-4">
                            <div className="d-flex flex-column justify-content-center mb-4" style={{ height: '435px' }}>
                                <div className="d-flex mb-6">
                                    <i className="fa fa-2x fa-map-marker-alt text-primary flex-shrink-0 mr-3"></i>
                                    <div className="mt-n1">
                                        <h5 className="text-black">{messages.phu_tung_honda}</h5>
                                        <p>{messages.content_diachi}</p>
                                    </div>
                                </div>
                                <div className="d-flex">
                                    <iframe
                                        src="https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d62690.63974697007!2d106.52971386909486!3d10.875053153202757!2m3...!1svi!2s"
                                        width="370" height="280" style={{ border: '0' }} allowFullScreen="" loading="lazy"
                                        referrerPolicy="no-referrer-when-downgrade"></iframe>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    )
}
export default Contacts;