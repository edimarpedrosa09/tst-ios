/*
 * Copyright (c) 2010-2023 Belledonne Communications SARL.
 *
 * This file is part of linphone-iphone
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

import SwiftUI

struct ThirdPartySipAccountWarningFragment: View {
	
	@ObservedObject private var sharedMainViewModel = SharedMainViewModel.shared
	@ObservedObject private var coreContext = CoreContext.shared
	@ObservedObject var accountLoginViewModel: AccountLoginViewModel
	
	@Environment(\.dismiss) var dismiss
	
	var body: some View {
		NavigationView {
			GeometryReader { geometry in
				ScrollView(.vertical) {
					VStack {
						ZStack {
							Image("mountain")
								.resizable()
								.scaledToFill()
								.frame(width: geometry.size.width, height: 100)
								.clipped()
							
							VStack(alignment: .leading) {
								HStack {
									Image("caret-left")
										.renderingMode(.template)
										.resizable()
										.foregroundStyle(Color.grayMain2c500)
										.frame(width: 25, height: 25, alignment: .leading)
										.padding(.all, 10)
										.padding(.top, -75)
										.padding(.leading, -10)
										.onTapGesture {
											withAnimation {
												dismiss()
											}
										}
									
									Spacer()
								}
								.padding(.leading)
							}
							.frame(width: geometry.size.width)
							
							Text("Use a SIP account")
								.default_text_style_white_800(styleSize: 20)
								.padding(.top, 20)
						}
						.padding(.top, 35)
						.padding(.bottom, 10)
						
						Spacer()
						
						VStack(alignment: .leading) {
							HStack {
								Spacer()
								HStack(alignment: .center) {
									Image("chat-teardrop-text-slash")
										.renderingMode(.template)
										.resizable()
										.foregroundStyle(Color.grayMain2c500)
										.frame(width: 20, height: 20, alignment: .leading)
								}
								.padding(16)
								.background(Color.grayMain2c200)
								.cornerRadius(40)
								.padding(.horizontal)
								
								HStack(alignment: .center) {
									Image("video-camera-slash")
										.renderingMode(.template)
										.resizable()
										.foregroundStyle(Color.grayMain2c500)
										.frame(width: 20, height: 20, alignment: .leading)
								}
								.padding(16)
								.background(Color.grayMain2c200)
								.cornerRadius(40)
								.padding(.horizontal)
								
								Spacer()
							}
							.padding(.bottom, 40)
							
							Text("Some features require a Linphone account, such as group messaging, video conferences...\n\n"
								 + "These features are hidden when you register with a third party SIP account.\n\n"
								 + "To enable it in a commercial projet, please contact us. ")
							.default_text_style(styleSize: 15)
							.multilineTextAlignment(.center)
							.padding(.bottom)
							
							HStack {
								Spacer()
								
								HStack {
									Text("[linphone.org/contact](https://linphone.org/contact)")
										.tint(Color.orangeMain500)
										.default_text_style_orange_600(styleSize: 15)
										.frame(height: 35)
								}
								.padding(.horizontal, 15)
								.cornerRadius(60)
								.overlay(
									RoundedRectangle(cornerRadius: 60)
										.inset(by: 0.5)
										.stroke(Color.orangeMain500, lineWidth: 1)
								)
								
								Spacer()
							}
							.padding(.vertical)
						}
						.frame(maxWidth: sharedMainViewModel.maxWidth)
						.padding(.horizontal, 20)
						
						Spacer()
						
						Button(action: {
							dismiss()
						}, label: {
							Text("I prefere create an account")
								.default_text_style_orange_600(styleSize: 20)
								.frame(height: 35)
								.frame(maxWidth: .infinity)
						})
						.padding(.horizontal, 20)
						.padding(.vertical, 10)
						.cornerRadius(60)
						.overlay(
							RoundedRectangle(cornerRadius: 60)
								.inset(by: 0.5)
								.stroke(Color.orangeMain500, lineWidth: 1)
						)
						.frame(maxWidth: sharedMainViewModel.maxWidth)
						.padding(.horizontal)
						
						NavigationLink(destination: {
							ThirdPartySipAccountLoginFragment(accountLoginViewModel: accountLoginViewModel)
						}, label: {
							Text("I understand")
								.default_text_style_white_600(styleSize: 20)
								.frame(height: 35)
								.frame(maxWidth: .infinity)
							
						})
						.padding(.horizontal, 20)
						.padding(.vertical, 10)
						.background(Color.orangeMain500)
						.cornerRadius(60)
						.frame(maxWidth: sharedMainViewModel.maxWidth)
						.padding(.horizontal)
						.padding(.bottom, geometry.safeAreaInsets.bottom.isEqual(to: 0.0) ? 20 : 0)
					}
					.frame(minHeight: geometry.size.height)
				}
			}
			.navigationTitle("")
		 	.navigationBarHidden(true)
		}
		.navigationViewStyle(StackNavigationViewStyle())
		.navigationTitle("")
		.navigationBarHidden(true)
	}
}

#Preview {
	ThirdPartySipAccountWarningFragment(accountLoginViewModel: AccountLoginViewModel())
}
