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
import linphonesw

struct ConversationsListBottomSheet: View {
	
	@Environment(\.dismiss) var dismiss
	
	private var idiom: UIUserInterfaceIdiom { UIDevice.current.userInterfaceIdiom }
	
	@State private var orientation = UIDevice.current.orientation
	
	@ObservedObject var conversationsListViewModel: ConversationsListViewModel
	
	@Binding var showingSheet: Bool
	
	var body: some View {
		VStack(alignment: .leading) {
			if idiom != .pad && (orientation == .landscapeLeft
								 || orientation == .landscapeRight
								 || UIScreen.main.bounds.size.width > UIScreen.main.bounds.size.height) {
				Spacer()
				HStack {
					Spacer()
					Button("Close") {
						if #available(iOS 16.0, *) {
							showingSheet.toggle()
						} else {
							showingSheet.toggle()
							dismiss()
						}
					}
				}
				.padding(.trailing)
			}
			
			Spacer()
			
			if conversationsListViewModel.selectedConversation != nil && !conversationsListViewModel.selectedConversation!.isReadOnly {
				Button {
					if conversationsListViewModel.selectedConversation != nil {
						conversationsListViewModel.markAsReadSelectedConversation()
						conversationsListViewModel.updateUnreadMessagesCount()
					}
					
					if #available(iOS 16.0, *) {
						if idiom != .pad {
							showingSheet.toggle()
						} else {
							showingSheet.toggle()
							dismiss()
						}
					} else {
						showingSheet.toggle()
						dismiss()
					}
				} label: {
					HStack {
						Image("envelope-simple")
							.renderingMode(.template)
							.resizable()
							.foregroundStyle(Color.grayMain2c500)
							.frame(width: 25, height: 25, alignment: .leading)
							.padding(.all, 10)
						Text("Marquer comme non lu")
							.default_text_style(styleSize: 16)
						Spacer()
					}
					.frame(maxHeight: .infinity)
				}
				.padding(.horizontal, 30)
				.background(Color.gray100)
				
				VStack {
					Divider()
				}
				.frame(maxWidth: .infinity)
				
				Button {
					if conversationsListViewModel.selectedConversation != nil {
						conversationsListViewModel.selectedConversation!.toggleMute()
					}
					
					if #available(iOS 16.0, *) {
						if idiom != .pad {
							showingSheet.toggle()
						} else {
							showingSheet.toggle()
							dismiss()
						}
					} else {
						showingSheet.toggle()
						dismiss()
					}
				} label: {
					HStack {
						Image(conversationsListViewModel.selectedConversation!.isMuted ? "bell" : "bell-slash")
							.renderingMode(.template)
							.resizable()
							.foregroundStyle(Color.grayMain2c500)
							.frame(width: 25, height: 25, alignment: .leading)
							.padding(.all, 10)
						Text(conversationsListViewModel.selectedConversation!.isMuted ? "Réactiver les notifications" : "Mettre en sourdine")
							.default_text_style(styleSize: 16)
						Spacer()
					}
					.frame(maxHeight: .infinity)
				}
				.padding(.horizontal, 30)
				.background(Color.gray100)
				
				VStack {
					Divider()
				}
				.frame(maxWidth: .infinity)
				
				if conversationsListViewModel.selectedConversation != nil
					&& !conversationsListViewModel.selectedConversation!.isGroup {
					Button {
						if !conversationsListViewModel.selectedConversation!.isGroup {
							conversationsListViewModel.selectedConversation!.call()
						}
						
						if #available(iOS 16.0, *) {
							if idiom != .pad {
								showingSheet.toggle()
							} else {
								showingSheet.toggle()
								dismiss()
							}
						} else {
							showingSheet.toggle()
							dismiss()
						}
						
					} label: {
						HStack {
							Image("phone")
								.renderingMode(.template)
								.resizable()
								.foregroundStyle(Color.grayMain2c500)
								.frame(width: 25, height: 25, alignment: .leading)
								.padding(.all, 10)
							Text("conversation_action_call")
								.default_text_style(styleSize: 16)
							Spacer()
						}
						.frame(maxHeight: .infinity)
					}
					.padding(.horizontal, 30)
					.background(Color.gray100)
					
					VStack {
						Divider()
					}
					.frame(maxWidth: .infinity)
				}
			}
			
			Button {
				conversationsListViewModel.selectedConversation!.deleteChatRoom()
				conversationsListViewModel.computeChatRoomsList(filter: "")
				
				if #available(iOS 16.0, *) {
					if idiom != .pad {
						showingSheet.toggle()
					} else {
						showingSheet.toggle()
						dismiss()
					}
				} else {
					showingSheet.toggle()
					dismiss()
				}
			} label: {
				HStack {
					Image("trash-simple")
						.renderingMode(.template)
						.resizable()
						.foregroundStyle(Color.redDanger500)
						.frame(width: 25, height: 25, alignment: .leading)
						.padding(.all, 10)
					Text("conversation_action_delete")
						.foregroundStyle(Color.redDanger500)
						.default_text_style(styleSize: 16)
					Spacer()
				}
				.frame(maxHeight: .infinity)
			}
			.padding(.horizontal, 30)
			.background(Color.gray100)
			
			if conversationsListViewModel.selectedConversation != nil && !conversationsListViewModel.selectedConversation!.isReadOnly {
				VStack {
					Divider()
				}
				.frame(maxWidth: .infinity)
				
				Button {
					if conversationsListViewModel.selectedConversation != nil {
						conversationsListViewModel.selectedConversation!.leave()
						conversationsListViewModel.selectedConversation!.isReadOnly = true
					}
					
					if #available(iOS 16.0, *) {
						if idiom != .pad {
							showingSheet.toggle()
						} else {
							showingSheet.toggle()
							dismiss()
						}
					} else {
						showingSheet.toggle()
						dismiss()
					}
				} label: {
					HStack {
						Image("sign-out")
							.renderingMode(.template)
							.resizable()
							.foregroundStyle(Color.grayMain2c500)
							.frame(width: 25, height: 25, alignment: .leading)
							.padding(.all, 10)
						Text("conversation_action_leave_group")
							.default_text_style(styleSize: 16)
						Spacer()
					}
					.frame(maxHeight: .infinity)
				}
				.padding(.horizontal, 30)
				.background(Color.gray100)
			}
		}
		.background(Color.gray100)
		.frame(maxWidth: .infinity)
		.onRotate { newOrientation in
			orientation = newOrientation
		}
	}
}

#Preview {
	ConversationsListBottomSheet(conversationsListViewModel: ConversationsListViewModel(), showingSheet: .constant(true))
}
